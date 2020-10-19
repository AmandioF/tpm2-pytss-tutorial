# Install TPM-PYTSS

-  Launch VM with image ubuntu-18.04, and RAM>=4GB

- Building TPM 2.0 emulator:

```bash
# Setup locale and language
# sudo ldconfig

sudo apt-get update -y 
# packages needed to compile libtpms

sudo apt-get install -y automake expect gnutls-bin libgnutls28-dev git gawk m4 socat fuse libfuse-dev tpm-tools libgmp-dev libtool libglib2.0-dev libnspr4-dev libnss3-dev libssl-dev libtasn1-dev

sudo apt-get clean

git clone -b v0.6.0 https://github.com/stefanberger/libtpms.git

sudo apt-get install autoconf

pushd libtpms
# configuring libtpms files to be installed in '/usr/lib'
./autogen.sh --with-openssl --with-tpm2 --prefix=/usr 
make -j `nproc`
sudo make install
popd
# rm -rf libtpms

sudo apt install -y autoconf findutils gnutls-dev net-tools python3-twisted sed socat softhsm2 libseccomp-dev
git clone -b v0.3.1  https://github.com/stefanberger/swtpm.git
pushd swtpm
./autogen.sh
./configure --prefix=/usr
make -j `nproc`
sudo make install
popd
# rm -rf swtpm

```

- Build QEMU

```bash
sudo apt install -y libspice-server-dev libspice-protocol-dev libpixman-1-dev
git clone --recursive https://github.com/qemu/qemu

pushd qemu

#sudo apt install ninja-build
#sudo bash configure --target-list=x86_64-softmmu --enable-spice

./configure --target-list=x86_64-softmmu --enable-spice # For x86_64 platform with -vga qxl spice enabled
make -j `nproc`
sudo make install
popd
# rm -rf qemu
```

-   We need to compile OVMF (an implementation of UEFI that supports TPM).
    To compile it from source we first need to build EDKII, which is a development environment for UEFI specifications.

```bash

sudo apt update -y && sudo apt upgrade -y && sudo apt install -y build-essential uuid-dev iasl git gcc-5 nasm python
git clone -b edk2-stable202002 --depth 1 --recursive https://github.com/tianocore/edk2.git
pushd edk2
make -C BaseTools
. edksetup.sh
. edksetup.sh BaseTools
# edit configuration to compile for X64 platform
sed -i 's|^ACTIVE_PLATFORM.*$|ACTIVE_PLATFORM = MdeModulePkg/MdeModulePkg.dsc|g' Conf/target.txt
sed -i 's|^TOOL_CHAIN_TAG.*$|TOOL_CHAIN_TAG = GCC5|g' Conf/target.txt
sed -i 's|^TARGET_ARCH.*$|TARGET_ARCH = X64|g' Conf/target.txt
sed -i 's|^MAX_CONCURRENT_THREAD_NUMBER.*$|MAX_CONCURRENT_THREAD_NUMBER = 5|g' Conf/target.txt 
build
# one result of the build is that you should have the HelloWorld UEFI application:
ls Build/MdeModule/DEBUG_*/*/HelloWorld.efi

```

-   Now we compile OVMF.
    We need to change the configuration target to compile OVMF and build it.
    Note: The following build commands take into account X64 architecture and default options for OVMF compilation by setting the 'build' command options -D TPM2_ENABLE=TRUE -D SECURE_BOOT_ENABLE=TRUE -D HTTP_BOOT_ENABLE=TRUE.
    If you need to customize more, you can edit OvmfPkg/OvmfPkgX64.dsc before and run 'build' without the options.
    Within edk2 dir, run the following commands:

```bash
# change configuration to compile OVMF
sed -i 's|^ACTIVE_PLATFORM.*$|ACTIVE_PLATFORM = OvmfPkg/OvmfPkgX64.dsc|g' Conf/target.txt
# build with TPM 2.0, Secure Boot and HTTP Boot enabled
build -D TPM2_ENABLE=TRUE -D SECURE_BOOT_ENABLE=TRUE -D HTTP_BOOT_ENABLE=TRUE
pushd

```

-   Finally you can proceed to create a VM via QEMU using the emulated TPM and the compiled UEFI.

```bash
# Define variables for configuring VM properties
VM_NAME=vm0 && VM_DISK_SIZE=20G && VM_RAM=1024 && VM_PASSWORD=password

# reuse OVMF_CODE but create a copy of the NVRAM file for this VM
# path to the OVMF_CODE.fd with TPM2_ENABLE enabled
BASE_OVMF_CODE_PATH=${HOME}/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_CODE.fd 
BASE_NVRAM_PATH=${HOME}/edk2/Build/OvmfX64/DEBUG_GCC5/FV/OVMF_VARS.fd
cp ${BASE_NVRAM_PATH} ${VM_NAME}_nvram.fd

# download an ubuntu ISO image and resize disk
sudo apt install -y axel && sudo axel -a -n 20 http://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-amd64-uefi1.img
OS_IMAGE_ORIG=$(pwd)/xenial-server-cloudimg-amd64-uefi1.img && OS_IMAGE=$(pwd)/disk-${VM_NAME}.img
qemu-img convert -O qcow2 $OS_IMAGE_ORIG $OS_IMAGE && qemu-img resize $OS_IMAGE $VM_DISK_SIZE

# choose an SSH port to access the VM from the host machine using 'ssh -p ${LOCALHOST_SSH_PORT} ubuntu@localhost'
LOCALHOST_SSH_PORT=2220
# choose the spice port to access with 'remote-viewer spice://127.0.0.1:${SPICE_PORT}'
SPICE_PORT=5930

# Create seed for cloud-init info
cat <<EOF >> seed
#cloud-config
password: ${VM_PASSWORD}
chpasswd: { expire: False }
ssh_pwauth: True
EOF

sudo apt install -y cloud-image-utils
SEED_IMAGE=seed.img
cloud-localds $SEED_IMAGE seed

# choose a path to place the Virtual TPM socket and other information
VTPM_DIR_PATH=/tmp/myvtpm0
sudo rm -rf ${VTPM_DIR_PATH}
sudo mkdir -p ${VTPM_DIR_PATH}
sudo chown tss:root ${VTPM_DIR_PATH}
sudo swtpm_setup --tpmstate ${VTPM_DIR_PATH} --createek --create-ek-cert --create-platform-cert --allow-signing --tpm2

# output of swtpm_setup
# ubuntu@tpm-demo:~$ sudo swtpm_setup --tpmstate ${VTPM_DIR_PATH} --createek --create-ek-cert --create-platform-cert --allow-signing --tpm2 
# Starting vTPM manufacturing as root:root @ Thu 21 May 2020 01:48:38 AM UTC
# TPM is listening on TCP port 59553.
# Successfully created EK with handle 0x81010001.
# Successfully created NVRAM area 0x01c00004 for EK template.
#  Invoking: /usr/share/swtpm/swtpm-localca --type ek --ek "a26077a30000982a3a1a0c234e6295a22f28f6fd00c76b5c8038a7790ed510b0b17dd5af81120f39fce362140f5eb05728af6fbef181edb92b79c81aabfcafeafe1ac5de1d09bf9c14bd416762868034b5b41f092a9dfdda2353e9318e713620d53dc0d09ac92e3accf8290ca4522a51c1270205f1ad0921b6a9051e3dc5f32d34e8b107ea62421d3b637f0029feb32b24b94d63078eb00a30b81cc6f25b8daaeab88beec5000b616e36d623e5325fb89878bcc737dc984ee52677b954b117ae9dd1cd7cbdcaae037e7e554d7293f1ec7ddff90dac055a9cdb9abbf1a1344b23465a39e15ea2234c0bc219e82f6f67c6e4a2dc929488197c2a1528cb114be6ab" --dir "/tmp/myvtpm0" --tpm-spec-family 2.0 --tpm-spec-level 00 --tpm-spec-revision 150 --tpm-manufacturer id:00001014 --tpm-model swtpm --tpm-version id:20170619 --configfile "/etc/swtpm-localca.conf" --optsfile "/etc/swtpm-localca.options" --tpm2
# swtpm-localca: Creating root CA and a local CA's signing key and issuer cert.
# swtpm-localca: Successfully created EK certificate locally.
#  Invoking: /usr/share/swtpm/swtpm-localca --type platform --ek "a26077a30000982a3a1a0c234e6295a22f28f6fd00c76b5c8038a7790ed510b0b17dd5af81120f39fce362140f5eb05728af6fbef181edb92b79c81aabfcafeafe1ac5de1d09bf9c14bd416762868034b5b41f092a9dfdda2353e9318e713620d53dc0d09ac92e3accf8290ca4522a51c1270205f1ad0921b6a9051e3dc5f32d34e8b107ea62421d3b637f0029feb32b24b94d63078eb00a30b81cc6f25b8daaeab88beec5000b616e36d623e5325fb89878bcc737dc984ee52677b954b117ae9dd1cd7cbdcaae037e7e554d7293f1ec7ddff90dac055a9cdb9abbf1a1344b23465a39e15ea2234c0bc219e82f6f67c6e4a2dc929488197c2a1528cb114be6ab" --dir "/tmp/myvtpm0" --tpm-spec-family 2.0 --tpm-spec-level 00 --tpm-spec-revision 150 --tpm-manufacturer id:00001014 --tpm-model swtpm --tpm-version id:20170619 --configfile "/etc/swtpm-localca.conf" --optsfile "/etc/swtpm-localca.options" --tpm2
# swtpm-localca: Successfully created platform certificate locally.
# Successfully created NVRAM area 0x01c00002 for EK certificate.
# Successfully created NVRAM area 0x01c08000 for platform certificate.
# Successfully activated PCR banks sha256,sha1 among sha1,sha256,sha384,sha512.
# Successfully authored TPM state.
# Ending vTPM manufacturing @ Thu 21 May 2020 01:48:40 AM UTC

sudo swtpm socket --tpmstate dir=${VTPM_DIR_PATH} --ctrl type=unixio,path=${VTPM_DIR_PATH}/swtpm-sock --log file=${VTPM_DIR_PATH}/vtpm.log,level=20 --tpm2 -d

# Create a UEFI flavored virtual machine using QEMU pointing to the socket. This will run in background.
sudo qemu-system-x86_64 -hda ${OS_IMAGE} -boot d -cdrom ${SEED_IMAGE} -m ${VM_RAM} -enable-kvm -chardev socket,id=chrtpm,path=${VTPM_DIR_PATH}/swtpm-sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::${LOCALHOST_SSH_PORT}-:22 -vga qxl -spice port=${SPICE_PORT},disable-ticketing -drive file=${BASE_OVMF_CODE_PATH},if=pflash,format=raw,unit=0,readonly=on -drive file=$(pwd)/${VM_NAME}_nvram.fd,if=pflash,format=raw,unit=1 &

```

-   Access VM

```bash
ssh -p ${LOCALHOST_SSH_PORT} ubuntu@localhost
```

-   Configure Secure Boot and IMA:

```bash
# Setup locale and language
sudo ldconfig

# Enable Secure Boot
sudo grub-install --uefi-secure-boot

# Enable IMA
sudo sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ima_policy=tcb"/' /etc/default/grub # use SHA1
# sudo sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ima_policy=tcb ima_hash=sha256"/' /etc/default/grub

# Update the GRUB 
sudo update-grub

# Create the ima directory to place custom IMA policy
sudo mkdir -p /etc/ima

# Create IMA policy script
sudo cat << EOF >> /etc/ima/ima-policy
#!/bin/sh
# PROC_SUPER_MAGIC
dont_measure fsmagic=0x9fa0
# SYSFS_MAGIC
dont_measure fsmagic=0x62656572
# DEBUGFS_MAGIC
dont_measure fsmagic=0x64626720
# TMPFS_MAGIC
dont_measure fsmagic=0x01021994
# RAMFS_MAGIC
dont_measure fsmagic=0x858458f6
# SECURITYFS_MAGIC
dont_measure fsmagic=0x73636673
# MEASUREMENTS
measure func=BPRM_CHECK
measure func=FILE_MMAP mask=MAY_EXEC
measure func=MODULE_CHECK uid=0
EOF
```
> #if cat doesn't work, do it with vim

```bash
sudo apt -y update
sudo apt -y install \
autoconf-archive \
libcmocka0 \
libcmocka-dev \
procps \
iproute2 \
build-essential \
git \
pkg-config \
gcc \
libtool \
automake \
libssl-dev \
uthash-dev \
autoconf \
doxygen \
libjson-c-dev \
libini-config-dev \
libcurl4-openssl-dev

wget http://ftpmirror.gnu.org/autoconf-archive/autoconf-archive-2019.01.06.tar.xz
tar -xvf autoconf-archive-2019.01.06.tar.xz 
pushd autoconf-archive-2019.01.06
./configure
make -j `nproc`
sudo make install 
popd

git clone https://github.com/tpm2-software/tpm2-tss.git

cd tpm2-tss/
cp ../autoconf-archive-2019.01.06/m4/*.m4 m4/ 
./bootstrap
./configure

make -j$(nproc)
sudo make install

sudo udevadm control --reload-rules && sudo udevadm trigger
sudo ldconfig

sudo mkdir -p /etc/ld.so.conf.d/
echo 'include /etc/ld.so.conf.d/*.conf' | sudo tee -a /etc/ld.so.conf
echo '/usr/local/lib' | sudo tee -a /etc/ld.so.conf.d/libc.conf
sudo ldconfig

sudo apt install python3-pip

sudo mkdir /etc/tpm2-tss/
sudo cp tpm2-tss/fapi-config.json /etc/tpm2-tss/
```

-   Install SWIG:
```bash
sudo apt-get -y install swig pkg-config
```

-   Install TPM Server:

```bash
git clone  https://github.com/kgoldman/ibmswtpm
cd ibmswtpm2
cd src
make 
export PATH="/home/ubuntu/ibmswtpm2/src/:$PATH"
```

-   Make Random test

```python

import sys
import random
import tempfile
import contextlib

from tpm2_pytss.fapi import FAPI, FAPIDefaultConfig
from tpm2_pytss.binding import *
from tpm2_pytss.util.simulator import Simulator


def main():
    # Usage information
    if len(sys.argv) != 2:
        print("Ouput N random bytes to stdout")
        print("Usage:length(between 8 and 32)")
        sys.exit(1)
    # Number of random bytes to get (between 8 and 32)
    length = int(sys.argv[1])
    # Input validation
    if length < 8 or length > 32:
        raise ValueError("length must be between 8 and 32")
    # Create a context stack
    with contextlib.ExitStack() as ctx_stack:
        # Create a simulator
        simulator = ctx_stack.enter_context(Simulator())
        # Create temporary directories to separate this example's state
        user_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
        log_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
        system_dir = ctx_stack.enter_context(tempfile.TemporaryDirectory())
        # Create the FAPI object
        fapi = FAPI(
            FAPIDefaultConfig._replace(
                user_dir=user_dir,
                system_dir=system_dir,
                log_dir=log_dir,
                tcti="mssim:port=%d" % (simulator.port,),
                tcti_retry=100,
                ek_cert_less=1,
            )
        )
        # Enter the context, create TCTI connection
        fapi_ctx = ctx_stack.enter_context(fapi)
        # Call Fapi_Provision
        fapi_ctx.Provision(None, None, None)
        # Create a pointer to the byte array we'll get back from GetRandom
        array = ctx_stack.enter_context(UINT8_PTR_PTR())
        # Call GetRandom and convert the resulting array to a Python bytearray
        value = to_bytearray(length, fapi_ctx.GetRandom(length, array))
        # Ensure we got the correct number of bytes
        if length != len(value):
            raise AssertionError("Requested %d bytes, got %d" % (length, len(value)))
        # Print bytes to stdout
        sys.stdout.buffer.write(value)


if __name__ == "__main__":
    main()

```

-   Run random test:

```bash
python3 random_test.py 10
```