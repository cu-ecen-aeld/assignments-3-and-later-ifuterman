#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.1.10
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # TODO: Add your kernel build steps here
    echo "Step 1. cleaning"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper 
    echo "Step 2. Configurating"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig
    echo "Step 3. Compiling"
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all
    # echo "Step 4. Modules"
    # make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} modules 
    echo "Step 4. Device tree"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} dtbs
fi

echo "Adding the Image in outdir"
cp "${OUTDIR}"/linux-stable/arch/${ARCH}/boot/Image "${OUTDIR}"


echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
echo "Create directories"
mkdir "${OUTDIR}"/rootfs
cd "${OUTDIR}"/rootfs
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p usr/bin usr/lib usr/sbin
mkdir -p var/log

echo "Installing busybox"
cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # TODO:  Configure busybox
    make distclean
    make defconfig
else
    cd busybox
fi

# TODO: 
echo "Make and install busybox"
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX="${OUTDIR}"/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

echo "Library dependencies"
${CROSS_COMPILE}readelf -a "${OUTDIR}"/rootfs/bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a "${OUTDIR}"/rootfs/bin/busybox | grep "Shared library"

# TODO: 
echo "Add library dependencies to rootfs"
SYSROOT=$(${CROSS_COMPILE}gcc -print-sysroot)
cp -r "$SYSROOT"/lib/* "$OUTDIR"/rootfs/lib
cp -r "$SYSROOT"/lib64/* "$OUTDIR"/rootfs/lib64

# TODO: 
echo "Make device nodes"
sudo mknod -m 666 "$OUTDIR"/rootfs/dev/null c 1 3
sudo mknod -m 600 "$OUTDIR"/rootfs/dev/console c 5 1

# TODO: 
echo "Clean and build the writer utility"
cd "$FINDER_APP_DIR"
make clean
make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE

# TODO: 
echo "Copy the finder related scripts and executables to the /home directory"
# on the target rootfs
cp writer "${OUTDIR}"/rootfs/home/
cp finder-test.sh "${OUTDIR}"/rootfs/home/
cp finder.sh "${OUTDIR}"/rootfs/home/
cp autorun-qemu.sh "${OUTDIR}"/rootfs/home/

#cp -r conf "${OUTDIR}"/rootfs/home/
mkdir -p "${OUTDIR}"/rootfs/home/conf
cp -rf conf/* "${OUTDIR}"/rootfs/home/conf
# cp conf/username.txt ${OUTDIR}/rootfs/home/conf
# cp conf/assignment.txt ${OUTDIR}/rootfs/home/conf


# TODO: 
echo "Chown the root directory"
cd "${OUTDIR}"/rootfs
sudo chown -R root:root *

# TODO: 
echo "Create initramfs.cpio.gz"
cd "${OUTDIR}"/rootfs
find . | cpio -H newc -ov --owner root:root > "${OUTDIR}"/initramfs.cpio
gzip -f "${OUTDIR}"/initramfs.cpio
