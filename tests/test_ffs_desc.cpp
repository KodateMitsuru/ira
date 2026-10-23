// SPDX-License-Identifier: AGPL-3.0-or-later
/* Host-side check of the FunctionFS descriptor blobs the daemon writes.
 *
 * The kernel parses these byte blobs with its own rules (f_fs.c
 * __ffs_data_got_descs -> ffs_do_descs -> ffs_do_single_desc) and refuses the
 * whole set on the first violation: a descriptor whose bLength is not exactly
 * the type's size, an endpoint address that differs between the fs/hs/ss sets,
 * a set whose endpoint or interface count differs from the others, a header
 * length that is not the write size.  None of that is visible until a device
 * enumerates, so it is checked here instead: the blobs below are the ones in
 * src/adbd/ira_ffs.cpp, included rather than copied.
 */
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

/* The translation unit itself: what is checked has to be what the daemon
 * writes, not a description of it. */
#include "../src/adb/ira_ffs.cpp"

namespace check {

static int fails;
static int groups;

static void ok(bool cond, const char *what) {
    if (cond) {
        std::printf("  PASS %s\n", what);
        return;
    }
    std::printf("  FAIL %s\n", what);
    fails++;
}

static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

struct walk_result {
    unsigned interfaces;
    unsigned eps;
    unsigned ep_addr[4];
    unsigned ep_mps[4];
    unsigned ep_attr[4];
    unsigned iface_class;
    unsigned iface_subclass;
    unsigned iface_protocol;
    unsigned iface_endpoints;   /* bNumEndpoints of the last interface */
    bool ok;
};

/* Walks `count` descriptors with the checks ffs_do_descs() makes, and returns
 * how many bytes they took. */
static walk_result walk(const char *label, const unsigned char *d, size_t avail,
                        unsigned count, unsigned strings_count, size_t *consumed) {
    walk_result r = {};
    size_t off = 0;

    r.ok = true;
    *consumed = 0;

    for (unsigned i = 0; i < count; i++) {
        if (off + 2 > avail) {
            std::printf("  FAIL %s: entry %u starts past the block\n", label, i);
            r.ok = false;
            return r;
        }
        const unsigned char *p = d + off;
        const unsigned bl = p[0];
        const unsigned bt = p[1];

        if (bl < 2 || off + bl > avail) {
            std::printf("  FAIL %s: entry %u has bLength %u in %zu bytes left\n",
                        label, i, bl, avail - off);
            r.ok = false;
            return r;
        }

        switch (bt) {
            case USB_DT_INTERFACE: {
                struct usb_interface_descriptor ds;

                memcpy(&ds, p, sizeof ds);
                if (bl != USB_DT_INTERFACE_SIZE) {
                    std::printf("  FAIL %s: interface bLength %u != %u\n", label, bl,
                                (unsigned)USB_DT_INTERFACE_SIZE);
                    r.ok = false;
                    break;
                }
                if (ds.bInterfaceNumber != 0) {
                    std::printf("  FAIL %s: bInterfaceNumber %u, expected 0\n", label,
                                ds.bInterfaceNumber);
                    r.ok = false;
                }
                if (ds.iInterface > strings_count) {
                    std::printf("  FAIL %s: iInterface %u with %u strings\n", label,
                                ds.iInterface, strings_count);
                    r.ok = false;
                }
                r.interfaces++;
                r.iface_class = ds.bInterfaceClass;
                r.iface_subclass = ds.bInterfaceSubClass;
                r.iface_protocol = ds.bInterfaceProtocol;
                r.iface_endpoints = ds.bNumEndpoints;
                break;
            }
            case USB_DT_ENDPOINT: {
                struct usb_endpoint_descriptor ds;

                memcpy(&ds, p, sizeof ds);
                if (bl != USB_DT_ENDPOINT_SIZE) {
                    std::printf("  FAIL %s: endpoint bLength %u != %u\n", label, bl,
                                (unsigned)USB_DT_ENDPOINT_SIZE);
                    r.ok = false;
                    break;
                }
                if ((ds.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK) == 0) {
                    std::printf("  FAIL %s: endpoint address %#x has no number\n", label,
                                ds.bEndpointAddress);
                    r.ok = false;
                }
                if (r.eps >= 4) {
                    std::printf("  FAIL %s: more endpoints than FFS allows\n", label);
                    r.ok = false;
                    break;
                }
                r.ep_addr[r.eps] = ds.bEndpointAddress;
                r.ep_mps[r.eps] = ds.wMaxPacketSize;
                r.ep_attr[r.eps] = ds.bmAttributes;
                r.eps++;
                break;
            }
            case USB_DT_SS_ENDPOINT_COMP:
                if (bl != USB_DT_SS_EP_COMP_SIZE) {
                    std::printf("  FAIL %s: ss companion bLength %u != %u\n", label, bl,
                                (unsigned)USB_DT_SS_EP_COMP_SIZE);
                    r.ok = false;
                }
                break;
            default:
                /* ffs_do_single_desc() accepts nothing else in a function set. */
                std::printf("  FAIL %s: descriptor type %#x is not allowed here\n", label, bt);
                r.ok = false;
                break;
        }
        off += bl;
    }
    *consumed = off;
    return r;
}

static void check_adb_set(void) {
    const unsigned char *b = (const unsigned char *)&kAdbDescs;
    const size_t blen = sizeof(kAdbDescs);

    std::printf("adb descriptor set (%zu bytes)\n", blen);
    ok(le32(b) == FUNCTIONFS_DESCRIPTORS_MAGIC_V2, "magic");
    ok(le32(b + 4) == blen, "declared header length is the write size");
    ok(le32(b + 8) == (FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
                       FUNCTIONFS_HAS_SS_DESC),
       "flags: fs, hs and ss sets");

    const unsigned fs = le32(b + 12);
    const unsigned hs = le32(b + 16);
    const unsigned ss = le32(b + 20);

    ok(fs == 3 && hs == 3 && ss == 5, "counts: 3 fs, 3 hs, 5 ss descriptors");

    const unsigned char *p = b + 24;
    size_t n1 = 0, n2 = 0, n3 = 0;
    walk_result r1 = walk("fs", p, blen - 24, fs, 1, &n1);
    walk_result r2 = walk("hs", p + n1, blen - 24 - n1, hs, 1, &n2);
    walk_result r3 = walk("ss", p + n1 + n2, blen - 24 - n1 - n2, ss, 1, &n3);

    ok(r1.ok && r2.ok && r3.ok, "every descriptor survives ffs_do_descs()' checks");
    ok(24 + n1 + n2 + n3 == blen, "the three sets fill the block exactly");

    ok(r1.interfaces == 1 && r2.interfaces == 1 && r3.interfaces == 1, "one interface per speed");
    ok(r1.eps == 2 && r2.eps == 2 && r3.eps == 2, "two endpoints per speed");
    ok(r1.iface_endpoints == 2 && r2.iface_endpoints == 2 && r3.iface_endpoints == 2,
       "bNumEndpoints is 2");
    ok(r1.iface_class == 0xff && r1.iface_subclass == 0x42 && r1.iface_protocol == 0x01 &&
           r2.iface_class == 0xff && r2.iface_subclass == 0x42 && r2.iface_protocol == 0x01 &&
           r3.iface_class == 0xff && r3.iface_subclass == 0x42 && r3.iface_protocol == 0x01,
       "interface is ADB's ff/42/01 at every speed");

    ok(r1.ep_addr[0] == (USB_DIR_OUT | 1) && r1.ep_addr[1] == (USB_DIR_IN | 2),
       "endpoints are ep1 OUT and ep2 IN");
    ok(r1.ep_addr[0] == r2.ep_addr[0] && r2.ep_addr[0] == r3.ep_addr[0] &&
           r1.ep_addr[1] == r2.ep_addr[1] && r2.ep_addr[1] == r3.ep_addr[1],
       "the endpoint address map is identical across speeds (f_fs.c:2280)");
    ok(r1.ep_attr[0] == USB_ENDPOINT_XFER_BULK && r1.ep_attr[1] == USB_ENDPOINT_XFER_BULK &&
           r2.ep_attr[0] == USB_ENDPOINT_XFER_BULK && r2.ep_attr[1] == USB_ENDPOINT_XFER_BULK &&
           r3.ep_attr[0] == USB_ENDPOINT_XFER_BULK && r3.ep_attr[1] == USB_ENDPOINT_XFER_BULK,
       "both endpoints are bulk");

    ok(r1.ep_mps[0] == 64 && r1.ep_mps[1] == 64, "full speed bulk max packet 64");
    ok(r2.ep_mps[0] == 512 && r2.ep_mps[1] == 512, "high speed bulk max packet 512");
    ok(r3.ep_mps[0] == 1024 && r3.ep_mps[1] == 1024, "super speed bulk max packet 1024");

    ok(IRA_BULK_CHUNK % r1.ep_mps[0] == 0 && IRA_BULK_CHUNK % r2.ep_mps[0] == 0 &&
           IRA_BULK_CHUNK % r3.ep_mps[0] == 0,
       "IRA_BULK_CHUNK is a whole number of packets at every speed");
    ok(IRA_FS_BULK_MAXPKT == r1.ep_mps[0] && IRA_HS_BULK_MAXPKT == r2.ep_mps[0] &&
           IRA_SS_BULK_MAXPKT == r3.ep_mps[0],
       "the declared limits are the ones the descriptors carry");
    groups++;
}

static void check_idle_set(void) {
    const unsigned char *b = (const unsigned char *)&kIdleDescs;
    const size_t blen = sizeof(kIdleDescs);

    std::printf("idle descriptor set (%zu bytes)\n", blen);
    ok(le32(b) == FUNCTIONFS_DESCRIPTORS_MAGIC_V2, "magic");
    ok(le32(b + 4) == blen, "declared header length is the write size");
    ok(le32(b + 8) == (FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
                       FUNCTIONFS_HAS_SS_DESC),
       "flags: fs, hs and ss sets");

    const unsigned fs = le32(b + 12);
    const unsigned hs = le32(b + 16);
    const unsigned ss = le32(b + 20);

    ok(fs == 1 && hs == 1 && ss == 1, "counts: one interface per speed, no endpoints");

    const unsigned char *p = b + 24;
    size_t n1 = 0, n2 = 0, n3 = 0;
    walk_result r1 = walk("idle/fs", p, blen - 24, fs, 1, &n1);
    walk_result r2 = walk("idle/hs", p + n1, blen - 24 - n1, hs, 1, &n2);
    walk_result r3 = walk("idle/ss", p + n1 + n2, blen - 24 - n1 - n2, ss, 1, &n3);

    ok(r1.ok && r2.ok && r3.ok, "the interfaces survive ffs_do_descs()' checks");
    ok(24 + n1 + n2 + n3 == blen, "the three sets fill the block exactly");
    ok(r1.eps == 0 && r2.eps == 0 && r3.eps == 0, "no endpoints at all");
    ok(r1.iface_endpoints == 0 && r2.iface_endpoints == 0 && r3.iface_endpoints == 0,
       "bNumEndpoints is 0");
    ok(r1.iface_class == 0xff && r1.iface_subclass == 0x00 && r1.iface_protocol == 0x00 &&
           r2.iface_class == 0xff && r2.iface_subclass == 0x00 && r2.iface_protocol == 0x00 &&
           r3.iface_class == 0xff && r3.iface_subclass == 0x00 && r3.iface_protocol == 0x00,
       "the idle interface is ff/00/00, which no adb host matches");
    groups++;
}

static void check_strings(void) {
    const unsigned char *b = (const unsigned char *)&kStrings;
    const size_t blen = sizeof(kStrings);

    std::printf("strings block (%zu bytes)\n", blen);
    ok(le32(b) == FUNCTIONFS_STRINGS_MAGIC, "magic");
    ok(le32(b + 4) == blen, "declared length is the write size");
    ok(le32(b + 8) == 1 && le32(b + 12) == 1, "one string, one language");
    ok(b[16] == 0x09 && b[17] == 0x04, "language is en-us");
    ok(memcmp(b + 18, IRA_STR_INTERFACE, sizeof(IRA_STR_INTERFACE)) == 0,
       "string 1 covers the interface's iInterface");
    groups++;
}

}  // namespace check

int main(void) {
    check::check_adb_set();
    check::check_idle_set();
    check::check_strings();

    if (check::fails) {
        std::printf("ffs descriptors: %d check(s) FAILED\n", check::fails);
        return 1;
    }
    std::printf("ffs descriptors: %d group(s), all checks passed\n", check::groups);
    return 0;
}
