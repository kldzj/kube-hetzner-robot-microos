#!/bin/bash
#
# install-microos.sh - Install openSUSE MicroOS on Hetzner Robot dedicated servers
#
# Designed for kube-hetzner compatibility on Hetzner Robot (dedicated) servers.
# Run from Hetzner Rescue System.
#
# Features:
#   - Auto-detects network configuration from rescue system
#   - Optional btrfs RAID1 when two disks are detected
#   - Optional vSwitch/VLAN configuration for Hetzner Cloud connectivity
#   - Full kube-hetzner compatibility (packages, SELinux policy, configs)
#
# Usage:
#   ./install-microos.sh --hostname myserver
#   ./install-microos.sh --hostname myserver --raid
#   ./install-microos.sh --hostname myserver \
#       --vswitch-vlan 4000 --vswitch-ip 10.0.1.2 --vswitch-gateway 10.0.1.1

set -euo pipefail

#######################################
# Configuration
#######################################

readonly VERSION="1.0.3"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die() {
	error "$*"
	exit 1
}

# Default values
MICROOS_IMAGE_URL="${MICROOS_IMAGE_URL:-https://download.opensuse.org/tumbleweed/appliances/openSUSE-MicroOS.x86_64-ContainerHost-OpenStack-Cloud.qcow2}"
MICROOS_IMAGE_SHA256_URL="${MICROOS_IMAGE_SHA256_URL:-${MICROOS_IMAGE_URL}.sha256}"
VERIFY_IMAGE="${VERIFY_IMAGE:-1}"
HOSTNAME=""
PACKAGES=""
SKIP_REBOOT=0
ENABLE_RAID=""
KERNEL_MODULES=""
SKIP_KERNEL_MODULES=""
DISABLE_SELINUX=""
SSH_PUBLIC_KEY=""
SSH_PUBLIC_KEY_URL=""

# DNS settings (Hetzner defaults)
DNS_SERVERS="${DNS_SERVERS:-185.12.64.1;185.12.64.2}"

# vSwitch settings
VSWITCH_VLAN_ID=""
VSWITCH_IP=""
VSWITCH_NETMASK="${VSWITCH_NETMASK:-24}"
VSWITCH_GATEWAY=""
VSWITCH_ROUTES=""
VSWITCH_MTU="${VSWITCH_MTU:-1400}"

# kube-hetzner required packages
readonly KUBE_HETZNER_PACKAGES="restorecond policycoreutils policycoreutils-python-utils setools-console audit bind-utils wireguard-tools fuse open-iscsi nfs-client xfsprogs cryptsetup lvm2 git cifs-utils bash-completion mtr tcpdump udica"

# Default kernel modules to enable (for kube-hetzner/CNI functionality)
readonly DEFAULT_KERNEL_MODULES="tun dm_crypt"

# Detected values (populated during execution)
INTERFACE=""
INTERFACE_MAC=""
IPV4_ADDRESS=""
IPV4_PREFIX=""
IPV4_GATEWAY=""
IPV6_ADDRESS=""
IPV6_GATEWAY=""
TARGET_DISK=""
SECOND_DISK=""

#######################################
# Utility functions
#######################################

# Wait for device nodes to settle
wait_for_devices() {
	udevadm settle --timeout=10 2>/dev/null || sleep 2
}

# Get partition suffix for disk (p for NVMe, empty for SATA)
get_part_suffix() {
	local disk="$1"
	[[ "$disk" == *"nvme"* ]] && echo "p" || echo ""
}

# Find btrfs root partition on a disk
find_btrfs_partition() {
	local disk="$1"
	local suffix
	suffix=$(get_part_suffix "$disk")

	for i in 4 3 2 1; do
		local part="${disk}${suffix}${i}"
		if [[ -b "$part" ]]; then
			local fstype
			fstype=$(blkid -o value -s TYPE "$part" 2>/dev/null || true)
			if [[ "$fstype" == "btrfs" ]]; then
				echo "$part"
				return 0
			fi
		fi
	done
	return 1
}

# Validate IPv4 address format
validate_ipv4() {
	local ip="$1"
	local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
	if [[ ! "$ip" =~ $regex ]]; then
		return 1
	fi
	IFS='.' read -ra octets <<<"$ip"
	for octet in "${octets[@]}"; do
		((octet <= 255)) || return 1
	done
	return 0
}

# Require an argument for a flag
require_arg() {
	local flag="$1"
	local value="${2:-}"
	[[ -z "$value" || "$value" == --* ]] && die "$flag requires an argument"
	echo "$value"
}

#######################################
# Parse command line arguments
#######################################
parse_args() {
	while [[ $# -gt 0 ]]; do
		case $1 in
		--image-url)
			MICROOS_IMAGE_URL=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--no-verify)
			VERIFY_IMAGE=0
			shift
			;;
		--hostname)
			HOSTNAME=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--disk)
			TARGET_DISK=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--second-disk)
			SECOND_DISK=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--raid)
			ENABLE_RAID=1
			shift
			;;
		--no-raid)
			ENABLE_RAID=0
			shift
			;;
		--kernel-modules)
			KERNEL_MODULES=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--skip-kernel-modules)
			SKIP_KERNEL_MODULES=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--ipv4)
			IPV4_ADDRESS=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--gateway)
			IPV4_GATEWAY=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--ipv6)
			IPV6_ADDRESS=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--ipv6-gateway)
			IPV6_GATEWAY=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--dns)
			DNS_SERVERS=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--ssh-key)
			SSH_PUBLIC_KEY=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--ssh-key-url)
			SSH_PUBLIC_KEY_URL=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--packages)
			PACKAGES=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--skip-reboot)
			SKIP_REBOOT=1
			shift
			;;
		--disable-selinux)
			DISABLE_SELINUX=1
			shift
			;;
		--vswitch-vlan)
			VSWITCH_VLAN_ID=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--vswitch-ip)
			VSWITCH_IP=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--vswitch-netmask)
			VSWITCH_NETMASK=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--vswitch-gateway)
			VSWITCH_GATEWAY=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--vswitch-routes)
			VSWITCH_ROUTES=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		--vswitch-mtu)
			VSWITCH_MTU=$(require_arg "$1" "${2:-}")
			shift 2
			;;
		-h | --help)
			show_help
			exit 0
			;;
		--version)
			echo "install-microos.sh version $VERSION"
			exit 0
			;;
		*)
			die "Unknown option: $1. Use --help for usage."
			;;
		esac
	done

	# Validate required arguments
	[[ -z "$HOSTNAME" ]] && die "Hostname is required. Use --hostname <name>"
	[[ "$HOSTNAME" == "rescue" ]] && die "Please specify a hostname (not 'rescue')"

	# Validate IP addresses if provided
	if [[ -n "$IPV4_ADDRESS" ]] && ! validate_ipv4 "$IPV4_ADDRESS"; then
		die "Invalid IPv4 address: $IPV4_ADDRESS"
	fi
	if [[ -n "$IPV4_GATEWAY" ]] && ! validate_ipv4 "$IPV4_GATEWAY"; then
		die "Invalid IPv4 gateway: $IPV4_GATEWAY"
	fi
	if [[ -n "$VSWITCH_IP" ]] && ! validate_ipv4 "$VSWITCH_IP"; then
		die "Invalid vSwitch IP: $VSWITCH_IP"
	fi

	# Validate vSwitch config completeness
	if [[ -n "$VSWITCH_VLAN_ID" && -z "$VSWITCH_IP" ]]; then
		die "--vswitch-vlan requires --vswitch-ip"
	fi
}

show_help() {
	cat <<'EOF'
Usage: install-microos.sh --hostname <name> [options]

Install openSUSE MicroOS on Hetzner Robot dedicated servers with kube-hetzner
compatibility. Run from Hetzner Rescue System.

Required:
  --hostname NAME        System hostname

Network Options:
  --ipv4 ADDRESS         IPv4 address (default: auto-detect from rescue)
  --gateway ADDRESS      IPv4 gateway (default: auto-detect)
  --ipv6 ADDRESS         IPv6 address (optional)
  --ipv6-gateway ADDR    IPv6 gateway (optional)
  --dns SERVERS          DNS servers, semicolon-separated (default: Hetzner DNS)

Storage Options:
  --disk DEVICE          Primary disk (default: auto-detect)
  --second-disk DEVICE   Second disk for RAID
  --raid                 Enable btrfs RAID1
  --no-raid              Disable RAID (single disk only)

Kernel Module Options:
  --kernel-modules LIST  Additional kernel modules to enable (comma-separated)
  --skip-kernel-modules  Skip default kernel modules (comma-separated)
                         Default modules: tun, dm_crypt

vSwitch/VLAN Options (for Hetzner Cloud connectivity):
  --vswitch-vlan ID      VLAN ID (4000-4091)
  --vswitch-ip ADDRESS   Private IP for vSwitch interface
  --vswitch-netmask N    Netmask bits (default: 24)
  --vswitch-gateway ADDR Gateway IP for vSwitch subnet
  --vswitch-routes CIDR  Routes via vSwitch gateway (comma-separated)
  --vswitch-mtu SIZE     MTU size (default: 1400)

Other Options:
  --image-url URL        Custom MicroOS image URL
  --no-verify            Skip image checksum verification
  --ssh-key KEY          SSH public key for root access
  --ssh-key-url URL      URL to fetch SSH public key
  --packages LIST        Additional packages to install
  --skip-reboot          Don't reboot after installation
  --disable-selinux      Disable SELinux (enabled by default)
  --version              Show version
  -h, --help             Show this help

Examples:
  # Basic install (auto-detects network from rescue system)
  ./install-microos.sh --hostname node1

  # With RAID1
  ./install-microos.sh --hostname node1 --raid

  # With custom DNS
  ./install-microos.sh --hostname node1 --dns "1.1.1.1;8.8.8.8"

  # With additional kernel modules
  ./install-microos.sh --hostname node1 --kernel-modules "overlay,br_netfilter"

  # Skip specific default kernel modules
  ./install-microos.sh --hostname node1 --skip-kernel-modules "dm_crypt"

  # Disable SELinux
  ./install-microos.sh --hostname node1 --disable-selinux

  # With vSwitch for Cloud connectivity
  ./install-microos.sh --hostname node1 \
      --vswitch-vlan 4000 --vswitch-ip 10.0.1.2 \
      --vswitch-gateway 10.0.1.1 --vswitch-routes "10.0.0.0/16"
EOF
}

#######################################
# Detect network configuration
#######################################
detect_network() {
	log "Detecting network configuration..."

	INTERFACE=$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.*dev \([a-z0-9]\+\).*/\1/p' || true)
	[[ -z "$INTERFACE" ]] && die "Could not detect network interface"

	INTERFACE_MAC=$(ip link show "$INTERFACE" | grep -oP 'link/ether \K[0-9a-f:]+' | head -1)
	[[ -z "$INTERFACE_MAC" ]] && die "Could not detect MAC address for $INTERFACE"

	if [[ -z "$IPV4_ADDRESS" ]]; then
		IPV4_ADDRESS=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
		[[ -z "$IPV4_ADDRESS" ]] && die "Could not detect IPv4 address"
	fi
	if [[ -z "$IPV4_GATEWAY" ]]; then
		IPV4_GATEWAY=$(ip -4 route show default | grep -oP '(?<=via\s)\d+(\.\d+){3}' | head -1)
		[[ -z "$IPV4_GATEWAY" ]] && die "Could not detect IPv4 gateway"
	fi
	IPV4_PREFIX=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -1 | cut -d/ -f2)
	: "${IPV4_PREFIX:=32}"

	if [[ -z "$IPV6_ADDRESS" ]]; then
		IPV6_ADDRESS=$(ip -6 addr show "$INTERFACE" scope global | grep -oP '(?<=inet6\s)[0-9a-f:]+' | head -1 || true)
	fi
	if [[ -z "$IPV6_GATEWAY" ]]; then
		IPV6_GATEWAY=$(ip -6 route show default | grep -oP '(?<=via\s)[0-9a-f:]+' | head -1 || true)
	fi

	log "Interface: $INTERFACE (MAC: $INTERFACE_MAC)"
	log "IPv4: $IPV4_ADDRESS/$IPV4_PREFIX via $IPV4_GATEWAY"
	log "DNS: $DNS_SERVERS"
	[[ -n "$IPV6_ADDRESS" ]] && log "IPv6: $IPV6_ADDRESS via $IPV6_GATEWAY"
}

#######################################
# Detect disks
#######################################
detect_disks() {
	log "Detecting disks..."

	local disks=()
	for disk in /dev/nvme*n1 /dev/sd[a-z]; do
		[[ -b "$disk" ]] && disks+=("$disk")
	done

	[[ ${#disks[@]} -eq 0 ]] && die "No suitable disks found"

	if [[ -n "$TARGET_DISK" ]]; then
		[[ ! -b "$TARGET_DISK" ]] && die "Specified disk not found: $TARGET_DISK"
	else
		TARGET_DISK="${disks[0]}"
	fi

	if [[ -n "$SECOND_DISK" ]]; then
		[[ ! -b "$SECOND_DISK" ]] && die "Specified second disk not found: $SECOND_DISK"
	elif [[ ${#disks[@]} -ge 2 ]]; then
		SECOND_DISK="${disks[1]}"
	fi

	log "Primary disk: $TARGET_DISK ($(lsblk -dn -o SIZE "$TARGET_DISK" 2>/dev/null || echo "?"))"

	if [[ -n "$SECOND_DISK" ]]; then
		log "Second disk: $SECOND_DISK ($(lsblk -dn -o SIZE "$SECOND_DISK" 2>/dev/null || echo "?"))"

		if [[ -z "$ENABLE_RAID" ]]; then
			echo ""
			warn "Two disks detected. Enable btrfs RAID1 for redundancy?"
			read -p "Enable RAID1? [Y/n]: " -r
			if [[ ! $REPLY =~ ^[Nn]$ ]]; then
				ENABLE_RAID=1
			else
				ENABLE_RAID=0
			fi
		fi
	else
		ENABLE_RAID=0
	fi

	[[ "$ENABLE_RAID" == "1" ]] && log "RAID1 will be enabled"
}

#######################################
# Install required packages in rescue
#######################################
install_rescue_deps() {
	log "Installing dependencies in rescue system..."
	apt-get update -qq || die "Failed to update package lists"
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
		qemu-utils wget curl parted gdisk btrfs-progs dosfstools e2fsprogs \
		cloud-guest-utils ||
		die "Failed to install rescue dependencies"
}

#######################################
# Download and verify MicroOS image
#######################################
download_image() {
	log "Downloading MicroOS image..."
	log "URL: $MICROOS_IMAGE_URL"

	IMAGE_FILE="/tmp/microos.qcow2"

	wget --timeout=30 --waitretry=5 --tries=5 --retry-connrefused \
		--progress=bar:force:noscroll \
		-O "$IMAGE_FILE" "$MICROOS_IMAGE_URL" ||
		die "Failed to download MicroOS image"

	log "Download complete: $(ls -lh "$IMAGE_FILE" | awk '{print $5}')"

	if [[ "$VERIFY_IMAGE" == "1" ]]; then
		log "Verifying image checksum..."
		local sha256_file="/tmp/microos.qcow2.sha256"

		if wget --timeout=10 -q -O "$sha256_file" "$MICROOS_IMAGE_SHA256_URL" 2>/dev/null; then
			local expected_hash actual_hash
			expected_hash=$(awk '{print $1}' "$sha256_file")
			actual_hash=$(sha256sum "$IMAGE_FILE" | awk '{print $1}')

			if [[ "$expected_hash" == "$actual_hash" ]]; then
				log "Checksum verified: $actual_hash"
			else
				die "Checksum mismatch! Expected: $expected_hash, Got: $actual_hash"
			fi
			rm -f "$sha256_file"
		else
			warn "Could not download checksum file, skipping verification"
		fi
	fi
}

#######################################
# Write image to disk
#######################################
write_image() {
	log "Cleaning up existing storage configurations..."
	mdadm --stop --scan 2>/dev/null || true
	vgchange -an 2>/dev/null || true

	log "Wiping $TARGET_DISK..."
	wipefs -af "$TARGET_DISK" || die "Failed to wipe $TARGET_DISK"

	if [[ "$ENABLE_RAID" == "1" ]]; then
		log "Wiping $SECOND_DISK..."
		wipefs -af "$SECOND_DISK" || die "Failed to wipe $SECOND_DISK"
	fi

	log "Writing MicroOS image to $TARGET_DISK..."
	qemu-img convert -p -f qcow2 -O host_device "$IMAGE_FILE" "$TARGET_DISK" ||
		die "Failed to write image to disk"

	sync
	partprobe "$TARGET_DISK"
	wait_for_devices

	resize_primary_partition

	if [[ "$ENABLE_RAID" == "1" ]]; then
		setup_raid
	fi

	resize_btrfs
}

#######################################
# Resize primary disk partition
#######################################
resize_primary_partition() {
	log "Resizing primary disk partition..."

	local root_part
	root_part=$(find_btrfs_partition "$TARGET_DISK") || {
		warn "Could not find root partition"
		return
	}

	local part_num
	part_num=$(echo "$root_part" | grep -oE '[0-9]+$')

	log "Growing partition $part_num on $TARGET_DISK..."
	growpart "$TARGET_DISK" "$part_num" || die "Failed to grow partition on $TARGET_DISK"

	partprobe "$TARGET_DISK"
	wait_for_devices

	local new_size
	new_size=$(lsblk -dn -o SIZE "$root_part" 2>/dev/null || echo "unknown")
	log "Primary partition $root_part now: $new_size"
}

#######################################
# Setup btrfs RAID1
#######################################
setup_raid() {
	log "Setting up btrfs RAID1..."

	local root_part
	root_part=$(find_btrfs_partition "$TARGET_DISK") || die "Could not find btrfs root partition"
	log "Primary root partition: $root_part"

	local part_num
	part_num=$(echo "$root_part" | grep -oE '[0-9]+$')
	log "Partition number: $part_num"

	log "Copying partition layout to $SECOND_DISK..."
	sfdisk -d "$TARGET_DISK" | sfdisk "$SECOND_DISK" || die "Failed to copy partition layout"
	partprobe "$SECOND_DISK"
	wait_for_devices

	local suffix2
	suffix2=$(get_part_suffix "$SECOND_DISK")
	local second_root="${SECOND_DISK}${suffix2}${part_num}"
	log "Secondary root partition: $second_root"

	log "Resizing partition $part_num on $SECOND_DISK..."
	growpart "$SECOND_DISK" "$part_num" || warn "growpart on second disk returned non-zero (may be OK if disk is smaller)"
	partprobe "$SECOND_DISK"
	wait_for_devices

	log "Formatting $second_root..."
	mkfs.btrfs -f "$second_root" || die "Failed to format $second_root"

	log "Adding second device to btrfs..."
	local mnt="/mnt/btrfs_raid"
	mkdir -p "$mnt"

	mount -t btrfs "$root_part" "$mnt" || die "Failed to mount for RAID setup"
	btrfs device add -f "$second_root" "$mnt" || {
		umount "$mnt"
		die "Failed to add second device"
	}

	log "Converting to RAID1 (this may take a while)..."
	btrfs balance start -dconvert=raid1 -mconvert=raid1 "$mnt" || {
		umount "$mnt"
		die "RAID1 balance failed"
	}

	log "RAID1 setup complete:"
	btrfs filesystem show "$mnt"

	umount "$mnt"
}

#######################################
# Resize btrfs filesystem
#######################################
resize_btrfs() {
	log "Resizing btrfs filesystem..."

	local root_part
	root_part=$(find_btrfs_partition "$TARGET_DISK") || {
		warn "Could not find root partition for btrfs resize"
		return
	}

	local mnt="/mnt/resize_tmp"
	mkdir -p "$mnt"

	if mount -t btrfs "$root_part" "$mnt" 2>/dev/null; then
		log "Resizing btrfs device 1..."
		btrfs filesystem resize 1:max "$mnt" || warn "btrfs resize device 1 failed"

		if [[ "$ENABLE_RAID" == "1" ]]; then
			log "Resizing btrfs device 2..."
			btrfs filesystem resize 2:max "$mnt" || warn "btrfs resize device 2 failed"
		fi

		log "Filesystem after resize:"
		btrfs filesystem usage "$mnt" 2>/dev/null | grep -E '(Device size|Free)' || true

		umount "$mnt"
	else
		warn "Could not mount filesystem for resize - may need manual resize after boot"
	fi
}

#######################################
# Configure the system
#######################################
configure_system() {
	log "Configuring system..."

	local root_part
	root_part=$(find_btrfs_partition "$TARGET_DISK") || die "Could not find root partition"
	log "Root partition: $root_part"

	local mnt="/mnt/microos"
	local mnt_root="/mnt/microos_root"
	mkdir -p "$mnt" "$mnt_root"

	mount -t btrfs "$root_part" "$mnt" || die "Failed to mount root filesystem"
	mount -t btrfs -o subvol=@/root "$root_part" "$mnt_root" || {
		umount "$mnt"
		die "Failed to mount @/root subvolume"
	}

	[[ ! -d "$mnt/etc" ]] && {
		umount "$mnt_root"
		umount "$mnt"
		die "Mounted filesystem does not contain /etc"
	}

	log "Filesystems mounted"

	log "Setting hostname: $HOSTNAME"
	echo "$HOSTNAME" >"$mnt/etc/hostname"

	configure_selinux "$mnt"
	configure_kernel_modules "$mnt"
	configure_network "$mnt"
	configure_ssh "$mnt_root"
	write_kube_hetzner_configs "$mnt" "$mnt_root"
	create_postinstall_script "$mnt_root" "${EXPORTED_KERNEL_MODULES:-}" "$DISABLE_SELINUX"

	sync
	umount "$mnt_root"
	umount "$mnt"

	log "System configuration complete"
}

#######################################
# Configure SELinux
#######################################
configure_selinux() {
	local root="$1"

	if [[ "$DISABLE_SELINUX" == "1" ]]; then
		log "Disabling SELinux..."

		# Method 1: Add selinux=0 to kernel command line (recommended method)
		if [[ -f "$root/etc/default/grub" ]]; then
			# Replace any existing selinux=1 with selinux=0, or add selinux=0 if not present
			if grep -q 'selinux=1' "$root/etc/default/grub"; then
				sed -i 's/selinux=1/selinux=0/g' "$root/etc/default/grub"
				log "Replaced selinux=1 with selinux=0 in /etc/default/grub"
			elif ! grep -q 'selinux=0' "$root/etc/default/grub"; then
				# Add selinux=0 to GRUB_CMDLINE_LINUX_DEFAULT
				sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 selinux=0"/' "$root/etc/default/grub"
				log "Added selinux=0 to kernel command line in /etc/default/grub"
			else
				log "selinux=0 already present in GRUB configuration"
			fi

			# Update GRUB configuration
			if chroot "$root" grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1; then
				log "GRUB configuration updated"
			else
				warn "Failed to update GRUB config (will be regenerated on boot)"
			fi
		else
			warn "GRUB configuration file not found"
		fi

		# Method 2: Set SELINUX=disabled in /etc/selinux/config (legacy, for compatibility)
		if [[ -f "$root/etc/selinux/config" ]]; then
			sed -i -E 's/^SELINUX=[a-z]+/SELINUX=disabled/' "$root/etc/selinux/config"
			log "SELinux disabled in /etc/selinux/config (legacy method)"
		else
			warn "SELinux config file not found, creating..."
			mkdir -p "$root/etc/selinux"
			echo "SELINUX=disabled" >"$root/etc/selinux/config"
			echo "SELINUXTYPE=targeted" >>"$root/etc/selinux/config"
		fi
	else
		log "SELinux enabled (enforcing mode)"
	fi
}

#######################################
# Configure kernel modules
#######################################
configure_kernel_modules() {
	local root="$1"

	# Build the list of modules to enable
	local modules=()

	# Add default modules (minus any skipped ones)
	if [[ -n "$SKIP_KERNEL_MODULES" ]]; then
		IFS=',' read -ra skip_array <<<"$SKIP_KERNEL_MODULES"
		for mod in $DEFAULT_KERNEL_MODULES; do
			local skip=0
			for skip_mod in "${skip_array[@]}"; do
				[[ "$mod" == "${skip_mod// /}" ]] && skip=1 && break
			done
			[[ "$skip" == "0" ]] && modules+=("$mod")
		done
	else
		# Add all default modules
		for mod in $DEFAULT_KERNEL_MODULES; do
			modules+=("$mod")
		done
	fi

	# Add any custom modules
	if [[ -n "$KERNEL_MODULES" ]]; then
		IFS=',' read -ra custom_array <<<"$KERNEL_MODULES"
		for mod in "${custom_array[@]}"; do
			modules+=("${mod// /}")
		done
	fi

	# Configure the modules
	if [[ ${#modules[@]} -gt 0 ]]; then
		log "Configuring kernel modules: ${modules[*]}"
		mkdir -p "$root/etc/modules-load.d"
		for mod in "${modules[@]}"; do
			echo "$mod" >>"$root/etc/modules-load.d/kube-hetzner.conf"
		done
		log "Kernel modules configured (will load on boot): ${modules[*]}"
	else
		log "No kernel modules configured"
	fi

	# Export the module list for use in post-install script
	EXPORTED_KERNEL_MODULES="${modules[*]}"
}

#######################################
# Configure NetworkManager
#######################################
configure_network() {
	local root="$1"

	log "Configuring network..."

	local nm_dir="$root/etc/NetworkManager/system-connections"
	mkdir -p "$nm_dir"

	mkdir -p "$root/etc/cloud/cloud.cfg.d"
	echo "network: {config: disabled}" >"$root/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"

	rm -f "$nm_dir"/cloud-init*.nmconnection 2>/dev/null || true

	local uuid
	uuid=$(cat /proc/sys/kernel/random/uuid)

	local ipv6_section="method=ignore"
	if [[ -n "$IPV6_ADDRESS" && -n "$IPV6_GATEWAY" ]]; then
		ipv6_section="method=manual
addresses=${IPV6_ADDRESS}/64
gateway=${IPV6_GATEWAY}"
	fi

	cat >"$nm_dir/main.nmconnection" <<EOF
[connection]
id=main
uuid=$uuid
type=ethernet
autoconnect=true
autoconnect-priority=100

[ethernet]
mac-address=${INTERFACE_MAC}

[ipv4]
method=manual
addresses=${IPV4_ADDRESS}/${IPV4_PREFIX}
gateway=${IPV4_GATEWAY}
dns=${DNS_SERVERS}
ignore-auto-dns=true

[ipv6]
${ipv6_section}
EOF

	chmod 600 "$nm_dir/main.nmconnection"

	if [[ -n "$VSWITCH_VLAN_ID" && -n "$VSWITCH_IP" ]]; then
		configure_vswitch "$root" "$uuid"
	fi

	{
		echo "$DNS_SERVERS" | tr ';' '\n' | while read -r dns; do
			[[ -n "$dns" ]] && echo "nameserver $dns"
		done
	} >"$root/etc/resolv.conf"
}

#######################################
# Configure vSwitch/VLAN
#######################################
configure_vswitch() {
	local root="$1"
	local parent_uuid="$2"

	log "Configuring vSwitch VLAN $VSWITCH_VLAN_ID..."

	local nm_dir="$root/etc/NetworkManager/system-connections"
	local uuid
	uuid=$(cat /proc/sys/kernel/random/uuid)

	local routes_section=""
	if [[ -n "$VSWITCH_ROUTES" && -n "$VSWITCH_GATEWAY" ]]; then
		local route_num=1
		IFS=',' read -ra ROUTE_ARRAY <<<"$VSWITCH_ROUTES"
		for route in "${ROUTE_ARRAY[@]}"; do
			routes_section+="route${route_num}=${route},${VSWITCH_GATEWAY}
"
			((route_num++))
		done
	fi

	cat >"$nm_dir/vswitch.nmconnection" <<EOF
[connection]
id=vswitch-${VSWITCH_VLAN_ID}
uuid=$uuid
type=vlan
autoconnect=true

[vlan]
flags=1
id=${VSWITCH_VLAN_ID}
parent=${parent_uuid}

[ethernet]
mtu=${VSWITCH_MTU}

[ipv4]
method=manual
addresses=${VSWITCH_IP}/${VSWITCH_NETMASK}
${routes_section}ignore-auto-dns=true
never-default=true

[ipv6]
method=ignore
EOF

	chmod 600 "$nm_dir/vswitch.nmconnection"

	mkdir -p "$root/etc/iproute2"
	if ! grep -q "^1 vswitch" "$root/etc/iproute2/rt_tables" 2>/dev/null; then
		echo "1 vswitch" >>"$root/etc/iproute2/rt_tables"
	fi

	log "vSwitch configured: VLAN $VSWITCH_VLAN_ID ($VSWITCH_IP/$VSWITCH_NETMASK, MTU $VSWITCH_MTU)"
	[[ -n "$VSWITCH_ROUTES" ]] && log "vSwitch routes: $VSWITCH_ROUTES via $VSWITCH_GATEWAY"
}

#######################################
# Configure SSH
#######################################
configure_ssh() {
	local root_home="$1"

	log "Configuring SSH..."

	local ssh_dir="$root_home/.ssh"
	mkdir -p "$ssh_dir"
	chmod 700 "$ssh_dir"

	local keys_file="$ssh_dir/authorized_keys"
	touch "$keys_file"

	if [[ -n "$SSH_PUBLIC_KEY_URL" ]]; then
		curl -sSL "$SSH_PUBLIC_KEY_URL" >>"$keys_file" 2>/dev/null || warn "Failed to fetch SSH key from URL"
	fi

	if [[ -n "$SSH_PUBLIC_KEY" ]]; then
		echo "$SSH_PUBLIC_KEY" >>"$keys_file"
	fi

	if [[ -f /root/.ssh/authorized_keys ]]; then
		cat /root/.ssh/authorized_keys >>"$keys_file" 2>/dev/null || true
	fi

	if [[ -s "$keys_file" ]]; then
		sort -u "$keys_file" >"$keys_file.tmp"
		mv "$keys_file.tmp" "$keys_file"
		chmod 600 "$keys_file"
	else
		warn "No SSH keys configured - you may not be able to log in!"
	fi
}

#######################################
# Write kube-hetzner configuration files
#######################################
write_kube_hetzner_configs() {
	local mnt_etc="$1"
	local mnt_root="$2"

	log "Writing kube-hetzner configuration files..."

	mkdir -p "$mnt_etc/etc/cloud/cloud.cfg.d"
	echo "network: {config: disabled}" >"$mnt_etc/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"

	cat >"$mnt_etc/etc/transactional-update.conf" <<'EOF'
REBOOT_METHOD=kured
EOF

	cat >"$mnt_etc/etc/zypp/repos.d/rancher-k3s-common.repo" <<'EOF'
[rancher-k3s-common-stable]
name=Rancher K3s Common (stable)
baseurl=https://rpm.rancher.io/k3s/stable/common/microos/noarch
enabled=1
gpgcheck=1
repo_gpgcheck=0
gpgkey=https://rpm.rancher.io/public.key
EOF

	mkdir -p "$mnt_etc/etc/ssh/sshd_config.d"
	cat >"$mnt_etc/etc/ssh/sshd_config.d/kube-hetzner.conf" <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/ssh/sftp-server
EOF

	cat >"$mnt_root/kube_hetzner_selinux.te" <<'EOF'
module kube_hetzner_selinux 1.0;

require {
    type kernel_t, bin_t, kernel_generic_helper_t, iscsid_t, iscsid_exec_t, var_run_t, var_lib_t,
        init_t, unlabeled_t, systemd_logind_t, systemd_hostnamed_t, container_t,
        cert_t, container_var_lib_t, etc_t, usr_t, container_file_t, container_log_t,
        container_share_t, container_runtime_exec_t, container_runtime_t, var_log_t, proc_t, io_uring_t, fuse_device_t, http_port_t,
        container_var_run_t;
    class key { read view };
    class file { open read execute execute_no_trans create link lock rename write append setattr unlink getattr watch };
    class sock_file { watch write create unlink };
    class unix_stream_socket { connectto };
    class unix_dgram_socket { sendto };
    class dir { add_name create getattr link lock read rename remove_name reparent rmdir setattr unlink search write watch };
    class lnk_file { create read getattr unlink };
    class system { module_request };
    class filesystem { associate };
    class bpf { map_create map_read map_write prog_load prog_run };
    class io_uring { sqpoll };
    class chr_file { getattr read write open ioctl };
    class tcp_socket { name_connect };
}

allow kernel_t bin_t:file { execute execute_no_trans };
allow kernel_t var_lib_t:file { open read };
allow kernel_generic_helper_t self:key { read view };
allow kernel_t kernel_t:bpf { map_create map_read map_write prog_load prog_run };
allow iscsid_t iscsid_exec_t:file { execute execute_no_trans };
allow iscsid_t var_run_t:sock_file { write };
allow iscsid_t var_run_t:dir { add_name remove_name write };
allow iscsid_t var_lib_t:dir { add_name write };
allow iscsid_t var_lib_t:file { create open write };
allow init_t unlabeled_t:dir { getattr search };
allow init_t unlabeled_t:lnk_file { getattr read };
allow init_t container_file_t:file { getattr open read };
allow init_t var_lib_t:lnk_file { getattr read };
allow init_t io_uring_t:io_uring { sqpoll };
allow systemd_logind_t unlabeled_t:dir search;
allow systemd_hostnamed_t unlabeled_t:dir search;
allow container_t cert_t:dir { search };
allow container_t cert_t:file { getattr open read };
allow container_t cert_t:lnk_file { getattr read };
allow container_t container_var_lib_t:file { watch };
allow container_t container_file_t:file { watch };
allow container_t etc_t:file { watch };
allow container_t usr_t:file { watch };
allow container_t var_log_t:file { open read };
allow container_t container_log_t:file { watch };
allow container_t container_share_t:file { watch };
allow container_t proc_t:filesystem { associate };
allow container_t fuse_device_t:chr_file { getattr read write open ioctl };
allow container_runtime_exec_t unlabeled_t:file { getattr open read execute execute_no_trans };
allow container_runtime_t container_var_run_t:sock_file { create unlink };
allow container_runtime_t http_port_t:tcp_socket { name_connect };
EOF
}

#######################################
# Create post-install script
#######################################
create_postinstall_script() {
	local mnt_root="$1"
	local kernel_modules="$2"
	local disable_selinux="$3"

	log "Creating post-install script..."

	cat >"$mnt_root/post-install.sh" <<EOFSCRIPT
#!/bin/bash
#
# MicroOS Post-Installation Script for kube-hetzner
#
# Run after first boot to install packages and configure the system.
# Requires a reboot after completion.
#
set -e

echo "=========================================="
echo "MicroOS Post-Install for kube-hetzner"
echo "=========================================="

PACKAGES="restorecond policycoreutils policycoreutils-python-utils setools-console audit bind-utils wireguard-tools fuse open-iscsi nfs-client xfsprogs cryptsetup lvm2 git cifs-utils bash-completion mtr tcpdump udica selinux-policy-devel $PACKAGES"

echo "Installing packages and configuring SELinux..."

# Load kernel modules immediately
EOFSCRIPT

	# Add module loading commands if modules are configured
	if [[ -n "$kernel_modules" ]]; then
		cat >>"$mnt_root/post-install.sh" <<EOFSCRIPT
echo 'Loading kernel modules: $kernel_modules'
for mod in $kernel_modules; do
    modprobe "\$mod" || echo "Warning: Failed to load module \$mod"
done
EOFSCRIPT
	fi

	# Add setenforce 0 if SELinux is disabled
	if [[ "$disable_selinux" == "1" ]]; then
		cat >>"$mnt_root/post-install.sh" <<EOFSCRIPT

echo 'Disabling SELinux immediately...'
setenforce 0 || echo "Warning: setenforce 0 failed"
EOFSCRIPT
	fi

	cat >>"$mnt_root/post-install.sh" <<EOFSCRIPT

transactional-update --non-interactive run bash -c "
set -e

echo '==> Installing packages...'
zypper --non-interactive install \$PACKAGES || echo 'Warning: Some packages may have failed'

echo '==> Importing Rancher GPG key...'
rpm --import https://rpm.rancher.io/public.key || true

echo '==> Installing k3s-selinux RPM...'
zypper --non-interactive install https://github.com/k3s-io/k3s-selinux/releases/download/v1.6.stable.1/k3s-selinux-1.6-1.sle.noarch.rpm || echo 'Warning: k3s-selinux may have failed'

echo '==> Compiling kube-hetzner SELinux policy...'
if [[ -f /root/kube_hetzner_selinux.te ]]; then
    cd /root
    if command -v checkmodule &>/dev/null; then
        checkmodule -M -m -o kube_hetzner_selinux.mod kube_hetzner_selinux.te
        semodule_package -o kube_hetzner_selinux.pp -m kube_hetzner_selinux.mod
        semodule -i kube_hetzner_selinux.pp
				setsebool -P virt_use_samba 1
				setsebool -P domain_kernel_load_modules 1
        echo 'SELinux policy installed'
        rm /root/install-selinux-policy.sh 2>/dev/null || true
    else
        echo 'Warning: checkmodule not available, run /root/install-selinux-policy.sh after reboot'
    fi
fi

echo '==> Disabling rebootmgr...'
systemctl disable rebootmgr.service || echo 'Warning: Failed to disable rebootmgr'

echo '==> Done!'
"

echo ""
echo "=========================================="
echo "Post-install complete!"
echo "=========================================="
echo ""
echo "Please reboot to activate the new snapshot:"
echo "  reboot"
echo ""
echo "Then, create your k3s config and install k3s with:"
echo "  curl -sfL https://get.k3s.io | INSTALL_K3S_SKIP_SELINUX_RPM=true INSTALL_K3S_VERSION=\"YOUR_VERSION\" INSTALL_K3S_EXEC=\"agent --config /etc/rancher/k3s/config.yaml\" sh -"
echo ""
EOFSCRIPT

	chmod +x "$mnt_root/post-install.sh"
}

#######################################
# Print summary
#######################################
print_summary() {
	# Build modules list for summary
	local modules=()
	if [[ -n "$SKIP_KERNEL_MODULES" ]]; then
		IFS=',' read -ra skip_array <<<"$SKIP_KERNEL_MODULES"
		for mod in $DEFAULT_KERNEL_MODULES; do
			local skip=0
			for skip_mod in "${skip_array[@]}"; do
				[[ "$mod" == "${skip_mod// /}" ]] && skip=1 && break
			done
			[[ "$skip" == "0" ]] && modules+=("$mod")
		done
	else
		for mod in $DEFAULT_KERNEL_MODULES; do
			modules+=("$mod")
		done
	fi
	if [[ -n "$KERNEL_MODULES" ]]; then
		IFS=',' read -ra custom_array <<<"$KERNEL_MODULES"
		for mod in "${custom_array[@]}"; do
			modules+=("${mod// /}")
		done
	fi

	echo ""
	log "=========================================="
	log "Installation Complete!"
	log "=========================================="
	echo ""
	log "Configuration Summary:"
	log "  Hostname:     $HOSTNAME"
	log "  Primary disk: $TARGET_DISK"
	[[ "$ENABLE_RAID" == "1" ]] && log "  RAID1 disk:   $SECOND_DISK"
	log "  IPv4:         $IPV4_ADDRESS/$IPV4_PREFIX via $IPV4_GATEWAY"
	[[ -n "$IPV6_ADDRESS" ]] && log "  IPv6:         $IPV6_ADDRESS"
	log "  DNS:          $DNS_SERVERS"
	[[ ${#modules[@]} -gt 0 ]] && log "  Kernel modules: ${modules[*]}"
	[[ "$DISABLE_SELINUX" == "1" ]] && log "  SELinux:      disabled" || log "  SELinux:      enabled"

	if [[ -n "$VSWITCH_VLAN_ID" ]]; then
		log "  vSwitch:      VLAN $VSWITCH_VLAN_ID ($VSWITCH_IP/$VSWITCH_NETMASK)"
		[[ -n "$VSWITCH_ROUTES" ]] && log "  vSwitch routes: $VSWITCH_ROUTES via $VSWITCH_GATEWAY"
	fi

	echo ""
	log "Next steps after reboot:"
	log "  1. SSH to root@$IPV4_ADDRESS"
	log "  2. Run: /root/post-install.sh"
	log "  3. Reboot again"
	log "  4. Install k3s or join to kube-hetzner cluster"
	echo ""
}

#######################################
# Main
#######################################
main() {
	log "=========================================="
	log "MicroOS Installer for Hetzner Robot v$VERSION"
	log "=========================================="

	detect_network
	detect_disks
	install_rescue_deps
	download_image
	write_image
	configure_system
	print_summary

	if [[ "$SKIP_REBOOT" == "1" ]]; then
		log "Skipping reboot as requested"
		log "Run 'reboot' when ready"
	else
		log "Rebooting in 5 seconds... (Ctrl+C to cancel)"
		sleep 5
		reboot
	fi
}

parse_args "$@"
main
