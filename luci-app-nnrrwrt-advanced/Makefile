# SPDX-License-Identifier: Apache-2.0

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI NNRRWrt advanced settings
LUCI_URL:=https://github.com/grislux55/nnrrwrt-packages/tree/main/luci-app-nnrrwrt-advanced
LUCI_DEPENDS:=+luci-base
LUCI_PKGARCH:=all
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_MAINTAINER:=grislux55 <jebchou.hg@gmail.com>

PKG_LICENSE:=Apache-2.0

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage: feed scanner marker; luci.mk generates the package rules.
