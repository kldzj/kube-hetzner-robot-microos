# MicroOS Installer for Hetzner Robot

Install openSUSE MicroOS on Hetzner Robot (dedicated) servers with full [kube-hetzner](https://github.com/mysticaltech/terraform-hcloud-kube-hetzner) compatibility.

## Features

- **Auto-detection**: Automatically detects network configuration from rescue system
- **RAID1 Support**: Optional btrfs RAID1 when two disks are detected
- **vSwitch/VLAN**: Configure Hetzner vSwitch for Cloud connectivity
- **kube-hetzner Ready**: Includes all required packages, SELinux policies, and configurations

## Quick Start

1. Boot your Hetzner Robot server into **Rescue System** (Linux 64-bit)

2. SSH into the rescue system

3. Download and run the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/kldzj/kube-hetzner-robot-microos/main/install-microos.sh -o install-microos.sh
chmod +x install-microos.sh
./install-microos.sh --hostname mynode
```

4. After reboot, SSH in and run the post-install script:

```bash
ssh root@YOUR_IP
/root/post-install.sh
```

The post-install script will automatically reboot after 10 seconds to activate the transactional-update snapshot.

If you need to skip the automatic reboot (not recommended), use `--skip-reboot`:
```bash
/root/post-install.sh --skip-reboot
```

5. After the second reboot, create your k3s config (see [docs/add-robot-server.md](https://github.com/mysticaltech/terraform-hcloud-kube-hetzner/blob/master/docs/add-robot-server.md#5-robot-node-k3s-agent-configuration)).

6. Make sure you can ping other nodes.

7. Install k3s using the provided script:

```bash
/root/install-k3s.sh
```

This script will:
- Verify your k3s config exists
- Check network connectivity
- Install k3s with the correct settings

## Usage

```
Usage: install-microos.sh --hostname <name> [options]

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

vSwitch/VLAN Options:
  --vswitch-vlan ID      VLAN ID (4000-4091)
  --vswitch-ip ADDRESS   Private IP for vSwitch interface
  --vswitch-netmask N    Netmask bits (default: 24)
  --vswitch-gateway ADDR Gateway IP for vSwitch subnet
  --vswitch-routes CIDR  Routes via vSwitch (comma-separated)
  --vswitch-mtu SIZE     MTU size (default: 1400)

K3s Options:
  --k3s-version VERSION  K3s version to install (e.g., v1.31.14+k3s1)

Other Options:
  --image-url URL        Custom MicroOS image URL
  --no-verify            Skip image checksum verification
  --ssh-key KEY          SSH public key for root access
  --ssh-key-url URL      URL to fetch SSH public key
  --packages LIST        Additional packages to install
  --skip-reboot          Don't reboot after installation
  --disable-selinux      Disable SELinux
  --version              Show version
  -h, --help             Show this help
```

## Examples

### Basic Installation

```bash
./install-microos.sh --hostname node1
```

### With RAID1

When two disks are detected, you'll be prompted to enable RAID1. Or specify explicitly:

```bash
./install-microos.sh --hostname node1 --raid
```

### With Custom DNS

```bash
./install-microos.sh --hostname node1 --dns "1.1.1.1;8.8.8.8"
```

### With Additional Kernel Modules

For advanced networking or storage features, add extra kernel modules:

```bash
./install-microos.sh --hostname node1 --kernel-modules "overlay,br_netfilter,vxlan"
```

### Skip Default Kernel Modules

If you don't need certain default modules (e.g., dm_crypt):

```bash
./install-microos.sh --hostname node1 --skip-kernel-modules "dm_crypt"
```

### Disable SELinux

If you prefer to run without SELinux (not recommended for production):

```bash
./install-microos.sh --hostname node1 --disable-selinux
```

### With Specific K3s Version

To install a specific k3s version:

```bash
./install-microos.sh --hostname node1 --k3s-version v1.31.14+k3s1
```

If you omit `--k3s-version`, the installer will use the latest k3s version.

### With vSwitch for Hetzner Cloud Connectivity

Connect your Robot server to Hetzner Cloud instances via vSwitch:

```bash
./install-microos.sh --hostname node1 \
    --vswitch-vlan 4000 \
    --vswitch-ip 10.0.1.2 \
    --vswitch-gateway 10.0.1.1 \
    --vswitch-routes "10.0.0.0/16"
```

If you set up a vSwitch with routes to your Cloud network, you'll want to set `flannel-iface` in your k3s config to your vSwitch interface, e.g. `enp35s0.4000`. You can find the correct interface name by running `nmcli` or `ip link`.

### Full Example

```bash
./install-microos.sh \
    --hostname k3s-node-1 \
    --raid \
    --dns "1.1.1.1;8.8.8.8" \
    --ssh-key "ssh-ed25519 AAAA... user@host" \
    --vswitch-vlan 4000 \
    --vswitch-ip 10.0.1.10 \
    --vswitch-gateway 10.0.1.1 \
    --vswitch-routes "10.0.0.0/8"
```

## How It Works

1. **Image Download**: Downloads the official openSUSE MicroOS ContainerHost Cloud image
2. **Checksum Verification**: Verifies the image integrity using SHA256
3. **Disk Setup**: Writes the image to disk and optionally configures RAID1
4. **Partition Resize**: Expands partitions to use full disk space
5. **Network Configuration**: Configures NetworkManager with static IP (uses MAC address matching)
6. **SELinux Configuration**: Configures SELinux policy (can be disabled with `--disable-selinux`)
7. **Kernel Modules**: Configures kernel modules to load on boot via `/etc/modules-load.d/`
8. **kube-hetzner Configs**: Installs required configs, repos, and SELinux policies
9. **Post-install Script**: Creates a script that runs `transactional-update` and automatically reboots
10. **K3s Install Script**: Creates `/root/install-k3s.sh` for easy k3s installation with optional version pinning

## RAID1 Details

When RAID1 is enabled:
- Uses native btrfs RAID1 (not mdadm)
- Both data and metadata are mirrored
- Self-healing capabilities
- Integrates with MicroOS snapshot system

## Kernel Modules

The installer automatically configures kernel modules required for Kubernetes and various CNI plugins:

**Default modules:**
- `tun` - Required for network tunneling (used by most CNI plugins)
- `dm_crypt` - Device mapper crypto support (for encrypted storage)

These modules are:
- Added to `/etc/modules-load.d/kube-hetzner.conf` to load on boot
- Loaded immediately during post-install for verification

## vSwitch Configuration

The vSwitch feature allows your Robot server to communicate with Hetzner Cloud instances:

1. Create a vSwitch in Hetzner Robot console
2. Attach it to your dedicated server
3. Create a subnet in your Cloud network
4. Use the installer with vSwitch options

The installer configures:
- VLAN interface with correct MTU (1400 for Hetzner)
- Static routes to Cloud network subnets
- Policy routing table for proper routing

## Included Packages

The post-install script installs these packages required by kube-hetzner:

- `policycoreutils`, `policycoreutils-python-utils` - SELinux utilities
- `k3s-selinux` - k3s SELinux policies
- `wireguard-tools` - WireGuard VPN
- `open-iscsi` - iSCSI support (for Longhorn)
- `nfs-client` - NFS support
- `cryptsetup`, `lvm2` - Storage utilities
- And more...

## Troubleshooting

### Cannot SSH after installation

1. Check that SSH keys were configured (from rescue system or `--ssh-key`)
2. Verify network configuration in rescue before install
3. Boot into rescue and check `/mnt/microos_root/.ssh/authorized_keys`

### RAID not using full disk space

Run these commands after boot:
```bash
mount -o remount,rw /
btrfs filesystem resize 1:max /
btrfs filesystem resize 2:max /
```

### vSwitch not working

1. Verify VLAN is attached in Hetzner Robot console
2. Check connection status: `nmcli connection show`
3. Verify routes: `ip route`

### `Device is busy` when preparing disks

Not sure about this one, I just enable the rescue system and reset the server again. Usually it works after that.