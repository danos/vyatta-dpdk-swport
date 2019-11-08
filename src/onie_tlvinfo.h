/*
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * The Definition of the TlvInfo EEPROM format can be found at onie.org or
 * github.com/onie
 */
#ifndef _ONIE_TLVINFO_H_
#define _ONIE_TLVINFO_H_

#define min(x, y)          ((x) > (y) ? (y) : (x))

/* tlvinf header: Layout of the header for the TlvInfo format */
struct __attribute__ ((__packed__)) tlvinfo_header {
	char signature[8];   /* EEPROM Tag "TlvInfo" */
	u_int8_t version;    /* Structure version */
	u_int16_t totallen;  /* Length of all data which follows */
};

/* Header Field Constants */
#define TLV_INFO_ID_STRING      "TlvInfo"
#define TLV_INFO_VERSION        0x01

/* TlvInfo TLV: Layout of a TLV field */
struct __attribute__ ((__packed__)) tlvinfo_tlv {
	u_int8_t type;
	u_int8_t length;
	u_int8_t value[0];
};

/* Maximum length of a TLV value in bytes */
#define TLV_VALUE_MAX_LEN        255

/*
 * The TLV Types.
 */
#define TLV_CODE_PRODUCT_NAME   0x21
#define TLV_CODE_PART_NUMBER    0x22
#define TLV_CODE_SERIAL_NUMBER  0x23
#define TLV_CODE_MAC_BASE       0x24
#define TLV_CODE_MANUF_DATE     0x25
#define TLV_CODE_DEVICE_VERSION 0x26
#define TLV_CODE_LABEL_REVISION 0x27
#define TLV_CODE_PLATFORM_NAME  0x28
#define TLV_CODE_ONIE_VERSION   0x29
#define TLV_CODE_MAC_SIZE       0x2A
#define TLV_CODE_MANUF_NAME     0x2B
#define TLV_CODE_MANUF_COUNTRY  0x2C
#define TLV_CODE_VENDOR_NAME    0x2D
#define TLV_CODE_DIAG_VERSION   0x2E
#define TLV_CODE_SERVICE_TAG    0x2F
#define TLV_CODE_VENDOR_EXT     0xFD
#define TLV_CODE_CRC_32         0xFE

/*
 *  Struct for displaying the TLV codes and names.
 */
struct tlv_code_desc {
	u_int8_t tag_type;
	const char *tag_name;
};

/*
 * List of TLV codes and names.
 */
static const struct tlv_code_desc tlv_code_list[] = {
	{TLV_CODE_PRODUCT_NAME, "Product Name"},
	{TLV_CODE_PART_NUMBER, "Part Number"},
	{TLV_CODE_SERIAL_NUMBER, "Serial Number"},
	{TLV_CODE_MAC_BASE, "Base MAC Address"},
	{TLV_CODE_MANUF_DATE, "Manufacture Date"},
	{TLV_CODE_DEVICE_VERSION, "Device Version"},
	{TLV_CODE_LABEL_REVISION, "Label Revision"},
	{TLV_CODE_PLATFORM_NAME, "Platform Name"},
	{TLV_CODE_ONIE_VERSION, "ONIE Version"},
	{TLV_CODE_MAC_SIZE, "MAC Addresses"},
	{TLV_CODE_MANUF_NAME, "Manufacturer"},
	{TLV_CODE_MANUF_COUNTRY, "Country Code"},
	{TLV_CODE_VENDOR_NAME, "Vendor Name"},
	{TLV_CODE_DIAG_VERSION, "Diag Version"},
	{TLV_CODE_SERVICE_TAG, "Service Tag"},
	{TLV_CODE_VENDOR_EXT, "Vendor Extension"},
	{TLV_CODE_CRC_32, "CRC-32"},
};
#endif
