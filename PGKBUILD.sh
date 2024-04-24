#!/usr/bin/env bash
echo "================== ENV variable ====================="
echo "BUILDROOT: ${BUILDROOT}"
echo "BUILDPATH: ${BUILDPATH}"
echo "VERSION: ${VERSION}"
echo "PACKPATH: ${PACKPATH}"
echo "Ustreamer branch: ${KVMD_USTREAMER_BRANCH}"
echo "KVM Front branch: ${KVMD_FRONT_BRANCH}"
echo "Build BASE APPS: ${BASE_APPS}"
# shellcheck disable=SC2153
echo "PACKNAME: ${PACKNAME}"
echo "FTP Server pack: ${FTPSERVERPATH}"
echo "====================================================="

mkdir -p "${BUILDPATH}" "${PACKPATH}"

# ============================================== APPS2 =========================================
if [ "${BASE_APPS}" == true ]; then
    echo "Start to build apps2..."
    # shellcheck disable=SC2164
    cd "${BUILDPATH}"
    cp -rf "${BUILDROOT}"/install/appsh2 "${BUILDPATH}"/
    wget "${FTP_SERVER}"/base/rcc-pikvmd-box-base.tar.gz && mv rcc-pikvmd-box-base.tar.gz apps2
    # shellcheck disable=SC2164
    cd "${BUILDROOT}"
    echo "Complete build apps2..."
fi

# ============================================== APPS1 =========================================
echo "Start to build apps1......"
APPS1_PATH=${BUILDPATH}/apps1_temp
mkdir -p "${APPS1_PATH}"

#echo "Start to build base deb packages..."
#DEB_PACKPATH=${PACKPATH}/deb
## shellcheck disable=SC2164
#cd "${DEB_PACKPATH}"
## shellcheck disable=SC2086
#tar -zcvf debian-packageas.tar.gz *.deb && cp -f debian-packageas.tar.gz ${APPS1_PATH}
#echo "Complete build deb packages..."

echo "Start to build python packages..."
PY_PACKPATH=${PACKPATH}/python
# shellcheck disable=SC2164
mkdir -p "${PY_PACKPATH}" && cd "${PY_PACKPATH}" && cp "${BUILDROOT}"/requirements.txt ./
pip download -d ./ -r "${BUILDROOT}"/requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
tar -zcvf python-packages.tar.gz ./* && cp -f python-packages.tar.gz "${APPS1_PATH}"
echo "Complete build python packages..."

echo "Start to build PKGINSTALL packages ..."
PKG_INSTALL_PATH=${BUILDROOT}/PKGINSTALL
# shellcheck disable=SC2164
cd "${PKG_INSTALL_PATH}"
tar -zcvf base-packages.tar.gz ./* && cp -f base-packages.tar.gz "${APPS1_PATH}"
echo "Complete build PKGINSTALL packages ..."

# shellcheck disable=SC2164
cd "${APPS1_PATH}"
tar -zcvf apps1 ./* && cp -f apps1 "${BUILDPATH}"
# shellcheck disable=SC2086
cp -rf "${BUILDROOT}"/install/appsh1 ${BUILDPATH}/
# shellcheck disable=SC2164
cd "${BUILDROOT}"
rm -rf "${APPS1_PATH}"
echo "Complete build apps1..."

# ============================================== APPS =========================================
echo "Start to build apps......"
APPS_PATH=${BUILDPATH}/apps_temp
mkdir -p "${APPS_PATH}"

echo "Start to build pikvm-ustreamer"
git clone -b "${KVMD_USTREAMER_BRANCH}" git@git.datrixinfo.com:rccbox/rcc-pikvm/pikvm-ustreamer.git && rm -rf pikvm-ustreamer/.git
cd pikvm-ustreamer && find ./ -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt && cd ..
tar -zcvf pikvmd-ustreamer.tar.gz ./pikvm-ustreamer && cp -f pikvmd-ustreamer.tar.gz "${APPS_PATH}"
echo "Complete build pikvm-ustreamer"

echo "Start to build pikvmd-backend"
# shellcheck disable=SC2164
cd "${BUILDROOT}" && mkdir -p pikvm-backend

# shellcheck disable=SC1073
for dir in configs contrib extras hid kvmd plugins scripts systems setup.py
do
  cp -rf ${dir} ./pikvm-backend
done
#git clone -b "${KVMD_BACKEND_BRANCH}" git@git.datrixinfo.com:rccbox/rcc-pikvm/pikvm-backend.git && rm -rf pikvm-backend/.git
cd pikvm-backend && find ./ -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt && cd ..
tar -zcvf pikvmd-backend.tar.gz ./pikvm-backend && cp -f pikvmd-backend.tar.gz "${APPS_PATH}"
echo "Complete build pikvmd-backend"

echo "Start to build pikvmd-front"
git clone -b "${KVMD_FRONT_BRANCH}" git@git.datrixinfo.com:rccbox/rcc-pikvm/pikvm-front.git && rm -rf pikvm-front/.git
cd pikvm-front && find ./ -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt && cd ..
tar -zcvf pikvmd-front.tar.gz ./pikvm-front && cp -f pikvmd-front.tar.gz "${APPS_PATH}"
echo "Complete build pikvmd-front"

# shellcheck disable=SC2164
cd "${APPS_PATH}"
tar -zcvf apps ./* && cp -f apps "${BUILDPATH}"
# shellcheck disable=SC2164
cd "${BUILDROOT}"
rm -rf "${APPS_PATH}"
echo "Complete build apps..."

# shellcheck disable=SC2164
cd "${BUILDPATH}"
cp -rf "${BUILDROOT}"/install/appsh "${BUILDPATH}"/
cp -rf "${BUILDROOT}"/install/pkginfo "${BUILDPATH}"/
echo "${PACK_NAME}${VERSION} Build${CUR_DATE}" >> version
find ./ -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt
packname=RccKVMD.zip
DatrixPack pack -file=./ -o=${packname}
mkdir -p kvmdpack && cp -rf ${packname} kvmdpack/ && cp -rf "${BUILDROOT}"/install/pkginfo kvmdpack/
cd ./kvmdpack && find ./ -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt
# shellcheck disable=SC2164
# shellcheck disable=SC2086
tar -zcvf "${PACKNAME}" ./* && cp -f "${PACKNAME}" ${BUILDROOT} && cd ${BUILDROOT}
echo "打包成功，${PACKNAME}"