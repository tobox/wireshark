/* packet-adwin.c
 * Routines for ADwin protocol dissection
 * Copyright 2010, Thomas Boehne <TBoehne[AT]ADwin.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

/* includes needed for wireshark */
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>

#include <stdio.h>

void proto_reg_handoff_adwin(void);
void proto_register_adwin(void);

/* ADwin default port for both TCP and UDP communication */
#define ADWIN_COMM_PORT 6543 /* Not IANA registered */

/* magic flags for tcp headers */
#define ADWIN_TCP_MAGIC_FLAG_REQUEST  0x42ad4214
#define ADWIN_TCP_MAGIC_FLAG_RESPONSE 0x42ad4253

/* lengths of valid UDP packet structures */
#define UDPH1_OLD_LENGTH              52
#define UDPH1_NEW_LENGTH              56
#define UDPR1_LENGTH                  32
#define UDPH2_LENGTH                 412 /* AFAIK: unused */
#define UDPR2_LENGTH                1008
#define UDPR3_LENGTH                1408
#define UDPR4_LENGTH                1416
#define GetDataSHPacket_LENGTH      1356
#define GetDataSHRequest_LENGTH       64

/* operating systems */
#define OS_WINDOWS                  0x00
#define OS_LINUX                    0x10
#define OS_JAVA                     0x20
#define OS_DOT_NET                  0x40
#define OS_GENERIC                  0x80
static const value_string osys_mapping[] = {
	{ OS_WINDOWS, "Windows"},
	{ OS_LINUX,   "Linux"},
	{ OS_JAVA,    "Java"},
	{ OS_DOT_NET, ".Net"},
	{ OS_GENERIC, "Generic TCP/IP Driver"},
	{ 0,          NULL },
};
static value_string_ext osys_mapping_ext = VALUE_STRING_EXT_INIT(osys_mapping);

/* error codes */
#define EC_OK                          0
#define EC_TIMEOUT_TO_LINK             1
#define EC_TIMEOUT_FROM_LINK           2
#define EC_TIMEOUT_FAST_TO_LINK        3
#define EC_TIMEOUT_FAST_FROM_LINK      4
#define	EC_TIMEOUT                     5
#define EC_MEMORY_ERROR             -100
#define EC_RETRY_UNKNOWN             -41
#define EC_ALREADY_PROCESSED         -40
#define EC_WRONG_BINARY_FILE         -35
#define EC_INVALID_PACKET_ORDER      -33
#define EC_FIFO_NOT_ENOUGH_DATA      -32
#define EC_DATA_TOO_SMALL            -31
#define EC_WRONG_VERSION             -30
#define EC_WRONG_SIZE                -26
#define EC_PACKET_TOO_LARGE          -25
#define EC_PACKET_ERROR              -20
#define EC_FILE_ERROR                -15
#define EC_TRY_LATER                 -10
#define EC_WRONG_PASSWORD             -5
#define EC_UDP_TIMEOUT                -1
static const value_string error_code_mapping[] = {
	{ EC_OK,                     "OK"},
	{ EC_TIMEOUT_TO_LINK,        "Timeout to link"},
	{ EC_TIMEOUT_FROM_LINK,      "Timeout from link"},
	{ EC_TIMEOUT_FAST_TO_LINK,   "Timeout fast to link"},
	{ EC_TIMEOUT_FAST_FROM_LINK, "Timeout fast from link"},
	{ EC_TIMEOUT,                "Timeout"},
	{ EC_MEMORY_ERROR,           "Memory error"},
	{ EC_RETRY_UNKNOWN,          "Retry unknown"},
	{ EC_ALREADY_PROCESSED,      "Already processed"},
	{ EC_WRONG_BINARY_FILE,      "Binary/Processor mismatch"},
	{ EC_INVALID_PACKET_ORDER,   "Invalid Packet order"},
	{ EC_FIFO_NOT_ENOUGH_DATA,   "Fifo has not enough data"},
	{ EC_DATA_TOO_SMALL,         "Data too small"},
	{ EC_WRONG_VERSION,          "Wrong version"},
	{ EC_WRONG_SIZE,             "Wrong size"},
	{ EC_PACKET_ERROR,           "Packet error"},
	{ EC_FILE_ERROR,             "File error"},
	{ EC_TRY_LATER,              "Try later"},
	{ EC_WRONG_PASSWORD,         "Wrong password"},
	{ EC_UDP_TIMEOUT,            "UDP timeout"},
	{ 0, NULL },
};
static value_string_ext error_code_mapping_ext = VALUE_STRING_EXT_INIT(error_code_mapping);

typedef enum {
	ADWIN_DATA_TYPE_INVALID = -1,
	ADWIN_BYTE = 1,    /* int_8 */
	ADWIN_SHORT = 2,   /* int_16 */
	ADWIN_LONG = 3,    /* int_32 */
	ADWIN_INTEGER = 4, /* int32, usually no used */
	ADWIN_FLOAT = 5,   /* float32 */
	ADWIN_DOUBLE = 6,  /* float64 */
	ADWIN_INT64 = 7,   /* int_64 */
	ADWIN_STRING = 8,  /* int_8, only T12 */
	ADWIN_FLOAT_OR_INTEGER = 9, /* workaround for wireshark */
	ADWIN_VARIANT = 20,
} adwin_data_type_t;

static const value_string data_type_mapping[] = {
	{ ADWIN_BYTE,    "int8 (byte)" },
	{ ADWIN_SHORT,   "int16 (short)" },
	{ ADWIN_LONG,    "int32 (long)" },
	{ ADWIN_INTEGER, "int32 (int)" },
	{ ADWIN_FLOAT,   "float" },
	{ ADWIN_DOUBLE,  "double" },
	{ ADWIN_INT64,   "int64" },
	{ ADWIN_STRING,  "string" },
	{ ADWIN_VARIANT, "variant" },
	{ ADWIN_FLOAT_OR_INTEGER, "float or int32" },
	{ ADWIN_DATA_TYPE_INVALID, "invalid type" },
	{ 0, NULL },
};
static value_string_ext data_type_mapping_ext = VALUE_STRING_EXT_INIT(data_type_mapping);

#define DISP_STR_PAR          0
#define DISP_STR_FPAR         1
#define DISP_STR_FPAR_DOUBLE  2
#define DISP_STR_DATA         3
#define DISP_STR_FIFO         4
#define DISP_STR_DATA_OR_FIFO 5
#define DISP_STR_MEMORY       6
#define DISP_STR_INVALID      7

const gchar* display_strings_data[] = { "Par", "FPar", "FPar_Double", "Data_", "Fifo_",
					"Data/Fifo", "Memory", "INVALID_TYPE"};

#define I_3PLUS1                           0
#define I_LOAD_BIN_FILE                    4
#define I_GET_DATA                         7
#define I_SET_DATA                         8
#define I_CREATE_DATA                     10
#define I_GET_PAR_ALL                     13
#define I_GET_WORKLOAD                    20
#define I_GET_FIFO                        24
#define I_SET_FIFO                        25
#define I_GET_DATA_N                      40
#define I_SET_DATA_N                      41
#define I_GET_FIFO_N                      42
#define I_SET_FIFO_N                      43
#define I_GET_DATA_INFO                   45
#define I_BOOT                            50
#define I_GET_DATA_TYPE                  100
#define I_GET_DATA_SHIFTED_HANDSHAKE     107
#define I_SET_DATA_LAST_STATUS           108
#define I_GET_FIFO_RETRY                 124
#define I_SET_FIFO_RETRY                 125
#define I_GET_DATA_SMALL                 207
#define I_TEST_VERSION                   255
#define I_AUTHENTICATE                   300
#define I_GET_ARM_VERSION               1000
#define I_GET_MEMORY                 1000000

static const value_string instruction_mapping[] = {
	{ I_3PLUS1,                     "3+1 instruction" },
	{ I_LOAD_BIN_FILE,              "Load binary file" },
	{ I_GET_DATA,                   "Get data" },
	{ I_SET_DATA,                   "Set data" },
	{ I_CREATE_DATA,                "Create data" },
	{ I_GET_PAR_ALL,                "Get all parameters" },
	{ I_GET_WORKLOAD,               "Get workload"},
	{ I_GET_FIFO,                   "Get fifo" },
	{ I_SET_FIFO,                   "Set fifo" },
	{ I_GET_DATA_N,                 "Get Data with variable byte size" },
	{ I_SET_DATA_N,                 "Set Data with variable byte size" },
	{ I_GET_FIFO_N,                 "Get Fifo with variable byte size" },
	{ I_SET_FIFO_N,                 "Set Fifo with variable byte size" },
	{ I_GET_DATA_INFO,              "Get Data/Fifo Information" },
	{ I_BOOT,                       "Boot" },
	{ I_GET_DATA_TYPE,              "Get data type" },
	{ I_GET_DATA_SHIFTED_HANDSHAKE, "Get data (shifted handshake)" },
	{ I_SET_DATA_LAST_STATUS,       "Get status of last set data" },
	{ I_GET_FIFO_RETRY,             "Get fifo - retry" },
	{ I_SET_FIFO_RETRY,             "Set fifo - retry" },
	{ I_GET_DATA_SMALL,             "Get data (small/fast)" },
	{ I_TEST_VERSION,               "Get/test version information" },
	{ I_AUTHENTICATE,               "Authenticate" },
	{ I_GET_ARM_VERSION,            "Get ARM-Version" },
	{ I_GET_MEMORY,                 "Get memory DSP" },
	{ 0, NULL },
};
static value_string_ext instruction_mapping_ext = VALUE_STRING_EXT_INIT(instruction_mapping);

/* 3+1 instructions */
#define I_3P1_GET_PAR                     1
#define I_3P1_START                       2
#define I_3P1_STOP                        3
#define I_3P1_GET_MEMORY_INFO             5
#define I_3P1_SET_PAR                     6
#define I_3P1_CLEAR_DATA                  9
#define I_3P1_GET_DATA_LENGTH            11
#define I_3P1_GET_DETAILED_MEM_INFO      12
#define I_3P1_CLEAR_PROCESS              14
#define I_3P1_ADC                        15
#define I_3P1_DAC                        16
#define I_3P1_GET_DIGIN                  17
#define I_3P1_SET_DIGOUT                 18
#define I_3P1_GET_DIGOUT                 19
#define I_3P1_CLEAR_FIFO                 21
#define I_3P1_GET_FIFO_EMPTY             22
#define I_3P1_GET_FIFO_COUNT             23
#define I_3P1_GET_DATA_STRING_SIZE       44
static const value_string instruction_3plus1_mapping[] = {
	{ I_3P1_GET_PAR,               "Get parameter"},
	{ I_3P1_START,                 "Start process"},
	{ I_3P1_STOP,                  "Stop process"},
	{ I_3P1_GET_MEMORY_INFO,       "Get memory info"},
	{ I_3P1_SET_PAR,               "Set parameter"},
	{ I_3P1_CLEAR_DATA,            "Clear data"},
	{ I_3P1_GET_DATA_LENGTH,       "Get data length"},
	{ I_3P1_GET_DETAILED_MEM_INFO, "Get detailed memory info"},
	{ I_3P1_CLEAR_PROCESS,         "Clear process"},
	{ I_3P1_ADC,                   "Get ADC value"},
	{ I_3P1_DAC,                   "Set DAC value"},
	{ I_3P1_GET_DIGIN,             "Get digital in"},
	{ I_3P1_SET_DIGOUT,            "Set digital out"},
	{ I_3P1_GET_DIGOUT,            "Get digital out"},
	{ I_3P1_CLEAR_FIFO,            "Clear fifo"},
	{ I_3P1_GET_FIFO_EMPTY,        "Get fifo empty"},
	{ I_3P1_GET_FIFO_COUNT,        "Get fifo full/count"},
	{ I_3P1_GET_DATA_STRING_SIZE,  "Get zero-terminated String Size" },
	{ 0, NULL },
};
static value_string_ext instruction_3plus1_mapping_ext = VALUE_STRING_EXT_INIT(instruction_3plus1_mapping);

static const value_string parameter_mapping[] = {
	{ 901 , "Status of Process No. 01"},
	{ 902 , "Status of Process No. 02"},
	{ 903 , "Status of Process No. 03"},
	{ 904 , "Status of Process No. 04"},
	{ 905 , "Status of Process No. 05"},
	{ 906 , "Status of Process No. 06"},
	{ 907 , "Status of Process No. 07"},
	{ 908 , "Status of Process No. 08"},
	{ 909 , "Status of Process No. 09"},
	{ 910 , "Status of Process No. 10"},
	{ 911 , "Processdelay for Process No. 01"},
	{ 912 , "Processdelay for Process No. 02"},
	{ 913 , "Processdelay for Process No. 03"},
	{ 914 , "Processdelay for Process No. 04"},
	{ 915 , "Processdelay for Process No. 05"},
	{ 916 , "Processdelay for Process No. 06"},
	{ 917 , "Processdelay for Process No. 07"},
	{ 918 , "Processdelay for Process No. 08"},
	{ 919 , "Processdelay for Process No. 09"},
	{ 920 , "Processdelay for Process No. 10"},
	{ 921 , "Processdelay for Process No. 11"},
	{ 922 , "Processdelay for Process No. 12"},
	{ 923 , "Processdelay for Process No. 13"},
	{ 924 , "Processdelay for Process No. 14"},
	{ 925 , "Processdelay for Process No. 15"},
	{ 926 , "Processdelay for Process No. 16"},
	{ 951 , "Debug Information of Process No. 01"},
	{ 952 , "Debug Information of Process No. 02"},
	{ 953 , "Debug Information of Process No. 03"},
	{ 954 , "Debug Information of Process No. 04"},
	{ 955 , "Debug Information of Process No. 05"},
	{ 956 , "Debug Information of Process No. 06"},
	{ 957 , "Debug Information of Process No. 07"},
	{ 958 , "Debug Information of Process No. 08"},
	{ 959 , "Debug Information of Process No. 09"},
	{ 960 , "Debug Information of Process No. 10"},
	{ 961 , "Debug Information of Process No. 11"},
	{ 962 , "Debug Information of Process No. 12"},
	{ 963 , "Debug Information of Process No. 13"},
	{ 964 , "Debug Information of Process No. 14"},
	{ 965 , "Debug Information of Process No. 15"},
	{ 966 , "Debug Information of Process No. 16"},
	{ 1001 , "Parameter No. 01"},
	{ 1002 , "Parameter No. 02"},
	{ 1003 , "Parameter No. 03"},
	{ 1004 , "Parameter No. 04"},
	{ 1005 , "Parameter No. 05"},
	{ 1006 , "Parameter No. 06"},
	{ 1007 , "Parameter No. 07"},
	{ 1008 , "Parameter No. 08"},
	{ 1009 , "Parameter No. 09"},
	{ 1010 , "Parameter No. 10"},
	{ 1011 , "Parameter No. 11"},
	{ 1012 , "Parameter No. 12"},
	{ 1013 , "Parameter No. 13"},
	{ 1014 , "Parameter No. 14"},
	{ 1015 , "Parameter No. 15"},
	{ 1016 , "Parameter No. 16"},
	{ 1017 , "Parameter No. 17"},
	{ 1018 , "Parameter No. 18"},
	{ 1019 , "Parameter No. 19"},
	{ 1020 , "Parameter No. 20"},
	{ 1021 , "Parameter No. 21"},
	{ 1022 , "Parameter No. 22"},
	{ 1023 , "Parameter No. 23"},
	{ 1024 , "Parameter No. 24"},
	{ 1025 , "Parameter No. 25"},
	{ 1026 , "Parameter No. 26"},
	{ 1027 , "Parameter No. 27"},
	{ 1028 , "Parameter No. 28"},
	{ 1029 , "Parameter No. 29"},
	{ 1030 , "Parameter No. 30"},
	{ 1031 , "Parameter No. 31"},
	{ 1032 , "Parameter No. 32"},
	{ 1033 , "Parameter No. 33"},
	{ 1034 , "Parameter No. 34"},
	{ 1035 , "Parameter No. 35"},
	{ 1036 , "Parameter No. 36"},
	{ 1037 , "Parameter No. 37"},
	{ 1038 , "Parameter No. 38"},
	{ 1039 , "Parameter No. 39"},
	{ 1040 , "Parameter No. 40"},
	{ 1041 , "Parameter No. 41"},
	{ 1042 , "Parameter No. 42"},
	{ 1043 , "Parameter No. 43"},
	{ 1044 , "Parameter No. 44"},
	{ 1045 , "Parameter No. 45"},
	{ 1046 , "Parameter No. 46"},
	{ 1047 , "Parameter No. 47"},
	{ 1048 , "Parameter No. 48"},
	{ 1049 , "Parameter No. 49"},
	{ 1050 , "Parameter No. 50"},
	{ 1051 , "Parameter No. 51"},
	{ 1052 , "Parameter No. 52"},
	{ 1053 , "Parameter No. 53"},
	{ 1054 , "Parameter No. 54"},
	{ 1055 , "Parameter No. 55"},
	{ 1056 , "Parameter No. 56"},
	{ 1057 , "Parameter No. 57"},
	{ 1058 , "Parameter No. 58"},
	{ 1059 , "Parameter No. 59"},
	{ 1060 , "Parameter No. 60"},
	{ 1061 , "Parameter No. 61"},
	{ 1062 , "Parameter No. 62"},
	{ 1063 , "Parameter No. 63"},
	{ 1064 , "Parameter No. 64"},
	{ 1065 , "Parameter No. 65"},
	{ 1066 , "Parameter No. 66"},
	{ 1067 , "Parameter No. 67"},
	{ 1068 , "Parameter No. 68"},
	{ 1069 , "Parameter No. 69"},
	{ 1070 , "Parameter No. 70"},
	{ 1071 , "Parameter No. 71"},
	{ 1072 , "Parameter No. 72"},
	{ 1073 , "Parameter No. 73"},
	{ 1074 , "Parameter No. 74"},
	{ 1075 , "Parameter No. 75"},
	{ 1076 , "Parameter No. 76"},
	{ 1077 , "Parameter No. 77"},
	{ 1078 , "Parameter No. 78"},
	{ 1079 , "Parameter No. 79"},
	{ 1080 , "Parameter No. 80"},
	{ 1101 , "Float-Parameter No. 01"},
	{ 1102 , "Float-Parameter No. 02"},
	{ 1103 , "Float-Parameter No. 03"},
	{ 1104 , "Float-Parameter No. 04"},
	{ 1105 , "Float-Parameter No. 05"},
	{ 1106 , "Float-Parameter No. 06"},
	{ 1107 , "Float-Parameter No. 07"},
	{ 1108 , "Float-Parameter No. 08"},
	{ 1109 , "Float-Parameter No. 09"},
	{ 1110 , "Float-Parameter No. 10"},
	{ 1111 , "Float-Parameter No. 11"},
	{ 1112 , "Float-Parameter No. 12"},
	{ 1113 , "Float-Parameter No. 13"},
	{ 1114 , "Float-Parameter No. 14"},
	{ 1115 , "Float-Parameter No. 15"},
	{ 1116 , "Float-Parameter No. 16"},
	{ 1117 , "Float-Parameter No. 17"},
	{ 1118 , "Float-Parameter No. 18"},
	{ 1119 , "Float-Parameter No. 19"},
	{ 1120 , "Float-Parameter No. 20"},
	{ 1121 , "Float-Parameter No. 21"},
	{ 1122 , "Float-Parameter No. 22"},
	{ 1123 , "Float-Parameter No. 23"},
	{ 1124 , "Float-Parameter No. 24"},
	{ 1125 , "Float-Parameter No. 25"},
	{ 1126 , "Float-Parameter No. 26"},
	{ 1127 , "Float-Parameter No. 27"},
	{ 1128 , "Float-Parameter No. 28"},
	{ 1129 , "Float-Parameter No. 29"},
	{ 1130 , "Float-Parameter No. 30"},
	{ 1131 , "Float-Parameter No. 31"},
	{ 1132 , "Float-Parameter No. 32"},
	{ 1133 , "Float-Parameter No. 33"},
	{ 1134 , "Float-Parameter No. 34"},
	{ 1135 , "Float-Parameter No. 35"},
	{ 1136 , "Float-Parameter No. 36"},
	{ 1137 , "Float-Parameter No. 37"},
	{ 1138 , "Float-Parameter No. 38"},
	{ 1139 , "Float-Parameter No. 39"},
	{ 1140 , "Float-Parameter No. 40"},
	{ 1141 , "Float-Parameter No. 41"},
	{ 1142 , "Float-Parameter No. 42"},
	{ 1143 , "Float-Parameter No. 43"},
	{ 1144 , "Float-Parameter No. 44"},
	{ 1145 , "Float-Parameter No. 45"},
	{ 1146 , "Float-Parameter No. 46"},
	{ 1147 , "Float-Parameter No. 47"},
	{ 1148 , "Float-Parameter No. 48"},
	{ 1149 , "Float-Parameter No. 49"},
	{ 1150 , "Float-Parameter No. 50"},
	{ 1151 , "Float-Parameter No. 51"},
	{ 1152 , "Float-Parameter No. 52"},
	{ 1153 , "Float-Parameter No. 53"},
	{ 1154 , "Float-Parameter No. 54"},
	{ 1155 , "Float-Parameter No. 55"},
	{ 1156 , "Float-Parameter No. 56"},
	{ 1157 , "Float-Parameter No. 57"},
	{ 1158 , "Float-Parameter No. 58"},
	{ 1159 , "Float-Parameter No. 59"},
	{ 1160 , "Float-Parameter No. 60"},
	{ 1161 , "Float-Parameter No. 61"},
	{ 1162 , "Float-Parameter No. 62"},
	{ 1163 , "Float-Parameter No. 63"},
	{ 1164 , "Float-Parameter No. 64"},
	{ 1165 , "Float-Parameter No. 65"},
	{ 1166 , "Float-Parameter No. 66"},
	{ 1167 , "Float-Parameter No. 67"},
	{ 1168 , "Float-Parameter No. 68"},
	{ 1169 , "Float-Parameter No. 69"},
	{ 1170 , "Float-Parameter No. 70"},
	{ 1171 , "Float-Parameter No. 71"},
	{ 1172 , "Float-Parameter No. 72"},
	{ 1173 , "Float-Parameter No. 73"},
	{ 1174 , "Float-Parameter No. 74"},
	{ 1175 , "Float-Parameter No. 75"},
	{ 1176 , "Float-Parameter No. 76"},
	{ 1177 , "Float-Parameter No. 77"},
	{ 1178 , "Float-Parameter No. 78"},
	{ 1179 , "Float-Parameter No. 79"},
	{ 1180 , "Float-Parameter No. 80"},
	{ 4891 , "Status of Process No. 11"},
	{ 4892 , "Status of Process No. 12"},
	{ 4893 , "Status of Process No. 13"},
	{ 4894 , "Status of Process No. 14"},
	{ 4895 , "Status of Process No. 15"},
	{ 4896 , "Status of Process No. 16"},
	{10000 , "Start Timing Analyzer"},
	{10001 , "Stop Timing Analyzer"},
	{ 0, NULL },
};
static value_string_ext parameter_mapping_ext = VALUE_STRING_EXT_INIT(parameter_mapping);

typedef enum {
	APT_UDPH1_old, APT_UDPH1_new, APT_UDPR1, APT_UDPR2, APT_UDPR3,
	APT_UDPR4, APT_GDSHP, APT_GDSHR
} adwin_packet_types_t;

static const value_string packet_type_mapping[] = {
	{ APT_UDPH1_old, "UDPH1 old"},
	{ APT_UDPH1_new, "UDPH1 new"},
	{ APT_UDPR1,	 "UDPR1"},
	{ APT_UDPR2,	 "UDPR2"},
	{ APT_UDPR3,	 "UDPR3"},
	{ APT_UDPR4,	 "UDPR4"},
	{ APT_GDSHP,	 "GDSHP"},
	{ APT_GDSHR,	 "GDSHR"},
	{ 0, NULL },
};
static value_string_ext packet_type_mapping_ext = VALUE_STRING_EXT_INIT(packet_type_mapping);

#define SET_PACKET_TYPE(tree, type)                              \
	proto_tree_add_int(tree, hf_adwin_packet_type, tvb, 0, tvb_captured_length(tvb), type);


/* Initialize the protocol and registered fields */
static int proto_adwin                = -1;

static unsigned int global_adwin_port = ADWIN_COMM_PORT;
static int global_adwin_dissect_data  = 1;

static int hf_adwin_address           = -1;
static int hf_adwin_armVersion        = -1;
static int hf_adwin_binfilesize       = -1;
static int hf_adwin_blob              = -1;
static int hf_adwin_blocksize         = -1;
static int hf_adwin_conn_count        = -1;
static int hf_adwin_count             = -1;
static int hf_adwin_complete_packets  = -1;
static int hf_adwin_data              = -1;
static int hf_adwin_data_int8         = -1;
static int hf_adwin_data_int8_hex     = -1;
static int hf_adwin_data_int16        = -1;
static int hf_adwin_data_int16_hex    = -1;
static int hf_adwin_data_int32        = -1;
static int hf_adwin_data_int32_hex    = -1;
static int hf_adwin_data_int64        = -1;
static int hf_adwin_data_int64_hex    = -1;
static int hf_adwin_data_float        = -1;
static int hf_adwin_data_double       = -1;
static int hf_adwin_data_string       = -1;
static int hf_adwin_data_no16         = -1;
static int hf_adwin_data_no32         = -1;
static int hf_adwin_data_packet_index = -1;
static int hf_adwin_data_size         = -1;
static int hf_adwin_data_type         = -1;
static int hf_adwin_dll_version       = -1;
static int hf_adwin_fifo_no16         = -1;
static int hf_adwin_fifo_no32         = -1;
static int hf_adwin_fifo_full         = -1;
static int hf_adwin_firmware_vers     = -1;
static int hf_adwin_firmware_vers_beta= -1;
static int hf_adwin_instruction       = -1;
static int hf_adwin_is_fifo           = -1;
static int hf_adwin_is_range          = -1;
static int hf_adwin_i3plus1           = -1;
static int hf_adwin_link_addr         = -1;
static int hf_adwin_mem_type          = -1;
static int hf_adwin_memsize           = -1;
static int hf_adwin_osys              = -1;
static int hf_adwin_packet_index      = -1;
static int hf_adwin_packet_no         = -1;
static int hf_adwin_packet_start      = -1;
static int hf_adwin_packet_end        = -1;
static int hf_adwin_gdsh_status       = -1;
static int hf_adwin_packet_type       = -1;
static int hf_adwin_parameter         = -1;
static int hf_adwin_password          = -1;
static int hf_adwin_process_no        = -1;
static int hf_adwin_processor         = -1;
static int hf_adwin_response_in       = -1;
static int hf_adwin_response_to       = -1;
static int hf_adwin_response_time     = -1;
static int hf_adwin_response_to_instruction = -1;
static int hf_adwin_response_to_i3plus1 = -1;
static int hf_adwin_retry_packet_index= -1;
static int hf_adwin_request_no        = -1;
static int hf_adwin_start_index       = -1;
static int hf_adwin_status_final      = -1;
static int hf_adwin_status_header     = -1;
static int hf_adwin_tcp_error         = -1;
static int hf_adwin_tcp_req_count     = -1;
static int hf_adwin_tcp_req_flag      = -1;
static int hf_adwin_tcp_req_len       = -1;
static int hf_adwin_tcp_resp_flag     = -1;
static int hf_adwin_timeout           = -1;
static int hf_adwin_timeout_size      = -1;
static int hf_adwin_unused            = -1;
static int hf_adwin_val1              = -1;
static int hf_adwin_val1f             = -1;
static int hf_adwin_val2              = -1;
static int hf_adwin_val2f             = -1;
static int hf_adwin_val3              = -1;
static int hf_adwin_val4              = -1;

/* Initialize the subtree pointers */
static gint ett_adwin                 = -1;
static gint ett_adwin_debug           = -1;

static dissector_handle_t data_handle;

/* response/request tracking */
typedef struct _adwin_transaction_t {
	guint32 req_frame;          /* frame number of request */
	guint32 rep_frame;          /* frame number of response */
	nstime_t req_time;          /* time of request (to calculate response time) */
	guint32 command;            /* command of request (required to make sense of response) */
	guint32 command3p1;         /* subcommand of request (required to make sense of response) */

	/* the following variables can store some (unstructured) information 
	 * of  the request that is needed to decode the response */
	guint32 additional_info1;
	guint32 additional_info2;
	guint32 additional_info3;
} adwin_transaction_t;

/* response/request tracking */
typedef struct _adwin_conv_info_t {
	wmem_map_t *pdus;
} adwin_conv_info_t;

typedef enum {
	ADWIN_REQUEST,
	ADWIN_RESPONSE
} adwin_direction_t;

/* Note: the padwin_trans parameter is (currently) only used for TCP sessions. */
static int
adwin_request_response_handling(tvbuff_t *tvb, packet_info *pinfo, proto_tree *adwin_tree, guint32 seq_num,
				adwin_direction_t direction, adwin_transaction_t **padwin_trans)
{
	conversation_t *conversation;
	adwin_conv_info_t *adwin_info;
	adwin_transaction_t *adwin_trans = NULL;

	/*
	 * Find or create a conversation for this connection.
	 */
	conversation = find_or_create_conversation(pinfo);

	/*
	 * Do we already have a state structure for this conv
	 */
	adwin_info = (adwin_conv_info_t *)conversation_get_proto_data(conversation, proto_adwin);
	if (!adwin_info) {
		/*
		 * No.  Attach that information to the conversation, and add
		 * it to the list of information structures.
		 */
		adwin_info = wmem_new(wmem_file_scope(), adwin_conv_info_t);
		adwin_info->pdus = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

		conversation_add_proto_data(conversation, proto_adwin, adwin_info);
	}
	if (!pinfo->fd->flags.visited) {
		switch (direction) {
		case ADWIN_REQUEST: 
			/* This is a request */
			adwin_trans = wmem_new(wmem_file_scope(), adwin_transaction_t);
			adwin_trans->req_frame = pinfo->fd->num;
			adwin_trans->rep_frame = 0;
			adwin_trans->req_time = pinfo->fd->abs_ts;
			wmem_map_insert(adwin_info->pdus, GUINT_TO_POINTER(seq_num), (void *)adwin_trans);
			break;
		case ADWIN_RESPONSE:
			adwin_trans = (adwin_transaction_t *)wmem_map_lookup(adwin_info->pdus, GUINT_TO_POINTER(seq_num));
			if (adwin_trans) {
				adwin_trans->rep_frame = pinfo->fd->num;
			}
			break;
		}
	} else {
		adwin_trans = (adwin_transaction_t *)wmem_map_lookup(adwin_info->pdus, GUINT_TO_POINTER(seq_num));
	}

	if (!adwin_trans) {
		/* create a "fake" adwin_trans structure */
		adwin_trans = wmem_new(wmem_packet_scope(), adwin_transaction_t);
		adwin_trans->req_frame = 0;
		adwin_trans->rep_frame = 0;
		adwin_trans->req_time = pinfo->fd->abs_ts;
	}

	if (adwin_tree) {
		/* print state tracking in the tree */
		if ((direction == ADWIN_REQUEST)) {
			/* This is a request */
			if (adwin_trans->rep_frame) {
				proto_item *it;
				
				it = proto_tree_add_uint(adwin_tree, hf_adwin_response_in,
							 tvb, 0, 0, adwin_trans->rep_frame);
				PROTO_ITEM_SET_GENERATED(it);
			}
		} else {
			/* This is a reply */
			if (adwin_trans->req_frame) {
				proto_item *it;
				nstime_t ns;
				
				it = proto_tree_add_uint(adwin_tree, hf_adwin_response_to,
							 tvb, 0, 0, adwin_trans->req_frame);
				PROTO_ITEM_SET_GENERATED(it);
				
				nstime_delta(&ns, &pinfo->fd->abs_ts, &adwin_trans->req_time);
				it = proto_tree_add_time(adwin_tree, hf_adwin_response_time, tvb, 0, 0, &ns);
				PROTO_ITEM_SET_GENERATED(it);
			}
		}
	}

	if (padwin_trans)
		*padwin_trans = adwin_trans;
	return 0;
}

gint32 bytes_per_value(guint data_type) {
	gint32 ADWIN_DATA_BYTES_PER_VALUE[] = {0, 1, 2, 4, 4, 4, 8, 8, 1, 4};

	if (data_type > sizeof(ADWIN_DATA_BYTES_PER_VALUE)/sizeof(ADWIN_DATA_BYTES_PER_VALUE[0])) {
		/* printf("Invalid data type %u\n", data_type); */
		return 0;
	}

	return ADWIN_DATA_BYTES_PER_VALUE[data_type];
}

void dissect_data(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_,
		  guint32 tvb_offset _U_, guint32 data_no _U_, guint32 start_index _U_, guint32 count _U_,
		  guint32 data_type _U_, guint32 data_string_type _U_) { }
#if 0
void dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		  guint32 tvb_offset, guint32 data_no, guint32 start_index, guint32 count,
		  guint32 data_type, guint32 data_string_type) {
	guint32 i;
	proto_item *item;
	const gchar* data_string;
	int bpv;

	bpv = bytes_per_value(data_type);
	
	if (! global_adwin_dissect_data) {
		call_dissector(data_handle, tvb_new_subset_length(tvb, tvb_offset, count * bpv), pinfo, tree);
		return;
	}

	if (data_string_type >= DISP_STR_INVALID) {
		data_string_type = DISP_STR_INVALID;
	}
	data_string = display_strings_data[data_string_type];
	
	for (i = 0; i < count; i++) {
		guint32 offset;
		offset = tvb_offset + i * bpv;
		
		switch (data_type) {
		case ADWIN_DATA_TYPE_INVALID:
		case ADWIN_VARIANT:
			/* not transferred over network */
			break;
		case ADWIN_BYTE: {
			guint8 value;
			value = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, bpv, "%s%.0d[%d]: %10d - 0x%02x",
					    data_string, data_no, start_index + i, value, value);
			item = proto_tree_add_item(tree, hf_adwin_data_int8,    tvb, offset, 1, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			item = proto_tree_add_item(tree, hf_adwin_data_int8_hex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			break;
		}
		case ADWIN_SHORT: {
			guint16 value;
			value = tvb_get_letohs(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, bpv, "%s%.0d[%d]: %10d - 0x%04x",
					    data_string, data_no, start_index + i, value, value);
			item = proto_tree_add_item(tree, hf_adwin_data_int16,    tvb, offset, 2, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			item = proto_tree_add_item(tree, hf_adwin_data_int16_hex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			break;
		}
		case ADWIN_LONG:
		case ADWIN_INTEGER: {
			guint32 value;
			value = tvb_get_letohl(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, bpv, "%s%.0d[%d]: %10d - 0x%08x",
					    data_string, data_no, start_index + i, value, value);
			item = proto_tree_add_item(tree, hf_adwin_data_int32,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			item = proto_tree_add_item(tree, hf_adwin_data_int32_hex, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			break;
		}
		case ADWIN_FLOAT: {
			gfloat value;
			value = tvb_get_letohieee_float(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, bpv, "%s%.0d[%d]: %10f",
					    data_string, data_no, start_index + i, value);
			item = proto_tree_add_item(tree, hf_adwin_data_float,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			break;
		}
		case ADWIN_FLOAT_OR_INTEGER: {
			guint32 value;
			gfloat fvalue;
			value = tvb_get_letohl(tvb, offset);
			fvalue = tvb_get_letohieee_float(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, bpv, "%s%.0d[%d]: %10d - 0x%08x - %10f",
					    data_string, data_no, start_index + i, value, value, fvalue);
			item = proto_tree_add_item(tree, hf_adwin_data_int32,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			item = proto_tree_add_item(tree, hf_adwin_data_int32_hex, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			item = proto_tree_add_item(tree, hf_adwin_data_float,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			break;
		}			
		case ADWIN_DOUBLE: {
			gfloat value;
			value = tvb_get_letohieee_double(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, bpv, "%s%.0d[%d]: %10e",
					    data_string, data_no, start_index + i, value);
			item = proto_tree_add_item(tree, hf_adwin_data_double,     tvb, offset, 8, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			break;
		}
		case ADWIN_INT64: {
			guint64 value;
			value = tvb_get_letoh64(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, bpv, "%s%.0d[%d]: %10li - 0x%016lx",
					    data_string, data_no, start_index + i, value, value);
			item = proto_tree_add_item(tree, hf_adwin_data_int64,     tvb, offset, 8, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			item = proto_tree_add_item(tree, hf_adwin_data_int64_hex, tvb, offset, 8, ENC_LITTLE_ENDIAN);
			PROTO_ITEM_SET_HIDDEN(item);
			break;
		}
		case ADWIN_STRING: {
			if (i == 0) {
				proto_tree_add_item(tree, hf_adwin_data_string,          tvb, offset, count, ENC_ASCII|ENC_NA);
			}
		}
		}
	}
}
#endif

static void
dissect_UDPH1_generic(tvbuff_t *tvb, packet_info *pinfo,
		      proto_tree *adwin_tree, proto_tree *adwin_debug_tree, gchar** info_string, const gchar* packet_name)
{
	guint32 i3plus1code = 0, instructionID, seq_num;

	instructionID = tvb_get_letohl(tvb, 0);
	*info_string = wmem_strdup_printf(wmem_packet_scope(), "%s: %s", packet_name,
				        val_to_str_ext(instructionID, &instruction_mapping_ext, "unknown instruction: %d"));

	if (instructionID == I_3PLUS1) {
		gchar *tmp = *info_string; //todo

		i3plus1code = tvb_get_letohl(tvb, 20);
		*info_string = wmem_strdup_printf(wmem_packet_scope(), "%s: %s", tmp, val_to_str_ext(i3plus1code, &instruction_3plus1_mapping_ext, "unknown 3+1 code: %d"));
	}

	/* Get the transaction identifier */
	seq_num = tvb_get_letohl(tvb, 4);

	adwin_request_response_handling(tvb, pinfo, adwin_tree, seq_num, ADWIN_REQUEST, NULL);

	if (! adwin_tree)
		return;

	SET_PACKET_TYPE(adwin_tree, APT_UDPH1_old);

	proto_tree_add_item(adwin_tree, hf_adwin_instruction,          tvb, 0,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_packet_index,         tvb, 4,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_password,             tvb, 8, 10, ENC_ASCII|ENC_NA);
	proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,        tvb, 18,  2, ENC_NA);

	switch(instructionID) {
	case I_3PLUS1:
		proto_tree_add_item(adwin_tree, hf_adwin_i3plus1,      tvb, 20,  4, ENC_LITTLE_ENDIAN);
		switch (i3plus1code) {
		case I_3P1_SET_PAR:
			proto_tree_add_item(adwin_tree, hf_adwin_parameter,     tvb, 24,  4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(adwin_tree, hf_adwin_val1,          tvb, 28,  4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(adwin_tree, hf_adwin_val1f,         tvb, 28,  4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 32,  4, ENC_NA);
			break;
		case I_3P1_GET_PAR:
			proto_tree_add_item(adwin_tree, hf_adwin_parameter,     tvb, 24,  4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 28,  8, ENC_NA);
			break;
		case I_3P1_GET_MEMORY_INFO:
		case I_3P1_GET_DETAILED_MEM_INFO:
			proto_tree_add_item(adwin_tree, hf_adwin_mem_type,      tvb, 24,  4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 28,  8, ENC_NA);
			break;
		case I_3P1_START:
		case I_3P1_STOP:
		case I_3P1_CLEAR_PROCESS:
			proto_tree_add_item(adwin_tree, hf_adwin_process_no,    tvb, 24,  4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 28,  8, ENC_NA);
			break;
		case I_3P1_GET_DATA_LENGTH:
			proto_tree_add_item(adwin_tree, hf_adwin_data_no32,     tvb, 24,  4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 28,  8, ENC_NA);
			break;
		case I_3P1_CLEAR_FIFO:
		case I_3P1_GET_FIFO_EMPTY:
		case I_3P1_GET_FIFO_COUNT:
			proto_tree_add_item(adwin_tree, hf_adwin_fifo_no32,     tvb, 24,  4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 28,  8, ENC_NA);
			break;
		default: ; /* should not happen */
			/* illegal values should be displayed properly
			   by 3plus1_mapping */
		}
		break;
	case I_BOOT:
		proto_tree_add_item(adwin_tree, hf_adwin_memsize,       tvb, 20,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_blocksize,     tvb, 24,  2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 26,  2, ENC_NA);
		proto_tree_add_item(adwin_tree, hf_adwin_processor,     tvb, 28,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_binfilesize,   tvb, 32,  4, ENC_LITTLE_ENDIAN);
		break;
	case I_LOAD_BIN_FILE:
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 20,  6, ENC_NA);
		proto_tree_add_item(adwin_tree, hf_adwin_blocksize,     tvb, 26,  2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_processor,     tvb, 28,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_binfilesize,   tvb, 32,  4, ENC_LITTLE_ENDIAN);
		break;
	case I_GET_WORKLOAD:
		proto_tree_add_item(adwin_tree, hf_adwin_instruction,   tvb, 20,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 24, 12, ENC_NA);
		break;
	case I_GET_DATA_TYPE:
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 20,  4, ENC_NA);
		proto_tree_add_item(adwin_tree, hf_adwin_data_no32,     tvb, 24,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_start_index,   tvb, 28,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 32,  4, ENC_NA);
		break;
	case I_GET_DATA:
	case I_SET_DATA:
		proto_tree_add_item(adwin_tree, hf_adwin_data_type,     tvb, 20,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_data_no16,     tvb, 24,  2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_blocksize,     tvb, 26,  2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_start_index,   tvb, 28,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_count,         tvb, 32,  4, ENC_LITTLE_ENDIAN);
		break;
	case I_GET_DATA_SHIFTED_HANDSHAKE:
		proto_tree_add_item(adwin_tree, hf_adwin_data_no16,     tvb, 20,  2, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_blocksize,     tvb, 22,  2, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_start_index,   tvb, 24,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_count,         tvb, 28,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 32,  4, ENC_NA);
		break;
	case I_GET_DATA_SMALL:
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 20,  4, ENC_NA);
		proto_tree_add_item(adwin_tree, hf_adwin_data_no16,     tvb, 24,  2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 26,  2, ENC_NA);
		proto_tree_add_item(adwin_tree, hf_adwin_start_index,   tvb, 28,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_count,         tvb, 32,  4, ENC_LITTLE_ENDIAN);
		break;
	case I_GET_PAR_ALL:
		proto_tree_add_item(adwin_tree, hf_adwin_start_index,   tvb, 20,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_count,         tvb, 24,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 28,  8, ENC_NA);
		break;
	case I_SET_DATA_LAST_STATUS:
		proto_tree_add_item(adwin_tree, hf_adwin_data_packet_index, tvb, 20,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 24,  12, ENC_NA);
		break;
	case I_GET_ARM_VERSION:
		proto_tree_add_item(adwin_tree, hf_adwin_armVersion,  tvb, 20,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused, tvb, 24, 12, ENC_NA);
		break;
	case I_GET_FIFO:
	case I_SET_FIFO:
		proto_tree_add_item(adwin_tree, hf_adwin_data_type,     tvb, 20,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_fifo_no16,     tvb, 24,  2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 26,  6, ENC_NA);
		proto_tree_add_item(adwin_tree, hf_adwin_count,         tvb, 32,  4, ENC_LITTLE_ENDIAN);
		break;
	case I_GET_FIFO_RETRY:
	case I_SET_FIFO_RETRY:
		proto_tree_add_item(adwin_tree, hf_adwin_data_type,     tvb, 20,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_fifo_no16,     tvb, 24,  2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 26,  2, ENC_NA);
		proto_tree_add_item(adwin_tree, hf_adwin_retry_packet_index, tvb, 28,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_count,         tvb, 32,  4, ENC_LITTLE_ENDIAN);
		break;
	case I_TEST_VERSION:
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 20,  16, ENC_NA);
		break;
	case I_GET_MEMORY:
		proto_tree_add_item(adwin_tree, hf_adwin_address,       tvb, 20,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_count,         tvb, 24,  4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 28,  8, ENC_NA);
		break;
	default: ; /* should not happen */
		/* illegal values should be displayed properly by
		   instruction_mapping */
	}

	proto_tree_add_item(adwin_debug_tree, hf_adwin_link_addr, tvb, 36,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_timeout,        tvb, 40,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_debug_tree, hf_adwin_osys,     tvb, 44,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,   tvb, 48,  4, ENC_NA);
}


static void
dissect_UDPH1_old(tvbuff_t *tvb, packet_info *pinfo,
		  proto_tree *adwin_tree, proto_tree *adwin_debug_tree, gchar** info_string)
{
	dissect_UDPH1_generic(tvb, pinfo, adwin_tree, adwin_debug_tree, info_string, "UDPH1 (old)");
}

static void
dissect_UDPH1_new(tvbuff_t *tvb, packet_info *pinfo,
		  proto_tree *adwin_tree, proto_tree *adwin_debug_tree,
		  gchar** info_string)
{
	gchar* dll_version_s;
	gint32 dll_i;

	dissect_UDPH1_generic(tvb, pinfo, adwin_tree, adwin_debug_tree, info_string, "UDPH1 (new)");

	if (! adwin_tree)
		return;

	SET_PACKET_TYPE(adwin_tree, APT_UDPH1_new);
	dll_i = tvb_get_letohl(tvb, 52);
	dll_version_s = wmem_strdup_printf(wmem_packet_scope(), "%d.%d.%d",
					dll_i / 1000000,
					(dll_i - dll_i / 1000000 * 1000000) / 1000,
					dll_i % 1000);

	proto_tree_add_string(adwin_debug_tree, hf_adwin_dll_version,
			      tvb, 52, 4, dll_version_s);
}

static void
dissect_UDPR1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *adwin_tree, proto_tree *adwin_debug_tree,
	      gchar** info_string)
{
	const gchar *status_string;
	guint32 seq_num, status;

	status = tvb_get_letohl(tvb, 0);
	status_string = try_val_to_str_ext(status, &error_code_mapping_ext);
	if (status_string) {
		*info_string = wmem_strdup_printf(wmem_packet_scope(), "UDPR1 Status: %s", status_string);
	} else {
		*info_string = wmem_strdup_printf(wmem_packet_scope(), "UDPR1 Undefined error code %d", status);
	}

	/* Get the transaction identifier */
	seq_num = tvb_get_letohl(tvb, 4);
	adwin_request_response_handling(tvb, pinfo, adwin_tree, seq_num, ADWIN_RESPONSE, NULL);

	if (! adwin_tree)
		return;

	SET_PACKET_TYPE(adwin_tree, APT_UDPR1);
	proto_tree_add_item(adwin_tree, hf_adwin_status_header, tvb,  0,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_packet_index,  tvb,  4,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_val1,          tvb,  8,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_val1f,         tvb,  8,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_val2,          tvb, 12,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_val3,          tvb, 16,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_val4,          tvb, 20,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 24,  8, ENC_NA);
}

static void
dissect_UDPR2(tvbuff_t *tvb, packet_info *pinfo,
	      proto_tree *adwin_tree, proto_tree *adwin_debug_tree,
	      gchar** info_string)
{
	const gchar *status_string;
	guint32 status, seq_num;

	status = tvb_get_letohl(tvb, 0);
	status_string = try_val_to_str_ext(status, &error_code_mapping_ext);
	if (status_string) {
	        *info_string = wmem_strdup_printf(wmem_packet_scope(), "UDPR2 Status: %s", status_string);
	} else {
		*info_string = wmem_strdup_printf(wmem_packet_scope(), "UDPR2 Undefined error code %d", status);
	}

	/* Get the transaction identifier */
	seq_num = tvb_get_letohl(tvb, 4);
	adwin_request_response_handling(tvb, pinfo, adwin_tree, seq_num, ADWIN_RESPONSE, NULL);

	if (! adwin_tree)
		return;

	SET_PACKET_TYPE(adwin_tree, APT_UDPR2);
	proto_tree_add_item(adwin_tree, hf_adwin_status_header,  tvb, 0,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_packet_index,   tvb, 4,  4, ENC_LITTLE_ENDIAN);
	
	dissect_data(tvb, pinfo, adwin_debug_tree, 8, 0, 0, 250, ADWIN_FLOAT_OR_INTEGER, DISP_STR_DATA_OR_FIFO);
}

static void
dissect_UDPR3(tvbuff_t *tvb, packet_info *pinfo,
	      proto_tree *adwin_tree, proto_tree *adwin_debug_tree)
{
	guint32 seq_num;

	/* Get the transaction identifier */
	seq_num = tvb_get_letohl(tvb, 0);
	adwin_request_response_handling(tvb, pinfo, adwin_tree, seq_num, ADWIN_RESPONSE, NULL);

	if (! adwin_tree)
		return;

	SET_PACKET_TYPE(adwin_tree, APT_UDPR3);
	proto_tree_add_item(adwin_tree, hf_adwin_packet_index,   tvb, 0,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_packet_no,      tvb, 4,  4, ENC_LITTLE_ENDIAN);

	dissect_data(tvb, pinfo, adwin_debug_tree, 8, 0, 0, 350, ADWIN_FLOAT_OR_INTEGER, DISP_STR_DATA_OR_FIFO);
}

static void
dissect_UDPR4(tvbuff_t *tvb, packet_info *pinfo,
	      proto_tree *adwin_tree, proto_tree *adwin_debug_tree, gchar** info_string)
{
	const gchar *status_string;
	guint32 data_type, status, seq_num;

	status = tvb_get_letohl(tvb, 0);
	status_string = try_val_to_str_ext(status, &error_code_mapping_ext);
	if (status_string) {
		*info_string = wmem_strdup_printf(wmem_packet_scope(), "UDPR4 Status: %s", status_string);
	} else {
		*info_string = wmem_strdup_printf(wmem_packet_scope(), "UDPR4 Undefined error code %d", status);
	}

	/* Get the transaction identifier */
	seq_num = tvb_get_letohl(tvb, 4);
	adwin_request_response_handling(tvb, pinfo, adwin_tree, seq_num, ADWIN_RESPONSE, NULL);

	if (! adwin_tree)
		return;

	SET_PACKET_TYPE(adwin_tree, APT_UDPR4);
	proto_tree_add_item(adwin_tree, hf_adwin_status_header,  tvb, 0,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_packet_index,   tvb, 4,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_packet_no,      tvb, 1408,  4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_data_type,      tvb, 1412,  4, ENC_LITTLE_ENDIAN);

	data_type = tvb_get_letohl(tvb, 1412);

	dissect_data(tvb, pinfo, adwin_debug_tree, 8, 0, 0, 350, data_type, DISP_STR_DATA_OR_FIFO);
}

static void
dissect_GDSHP(tvbuff_t *tvb, packet_info *pinfo,
	      proto_tree *adwin_tree, proto_tree *adwin_debug_tree)
{
	guint32 seq_num;

	/* Get the transaction identifier */
	seq_num = tvb_get_ntohl(tvb, 0);
	adwin_request_response_handling(tvb, pinfo, adwin_tree, seq_num, ADWIN_RESPONSE, NULL);

	if (! adwin_tree)
		return;

	SET_PACKET_TYPE(adwin_tree, APT_GDSHP);
	proto_tree_add_item(adwin_tree, hf_adwin_packet_index,   tvb, 0,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_packet_no,      tvb, 4,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_unused,         tvb, 8,  4, ENC_NA);

	dissect_data(tvb, pinfo, adwin_debug_tree, 12, 0, 0, 336, ADWIN_FLOAT_OR_INTEGER, DISP_STR_DATA_OR_FIFO);
}

static void
dissect_GDSHR(tvbuff_t *tvb, packet_info *pinfo,
	      proto_tree *adwin_tree, proto_tree *adwin_debug_tree)
{
	guint32 is_range, packet_start, packet_end, seq_num;
	proto_item *ti;

	/* Get the transaction identifier */
	seq_num = tvb_get_ntohl(tvb, 0);
	adwin_request_response_handling(tvb, pinfo, adwin_tree, seq_num, ADWIN_RESPONSE, NULL);

	if (! adwin_tree)
		return;

	SET_PACKET_TYPE(adwin_tree, APT_GDSHR);
 	proto_tree_add_item(adwin_tree, hf_adwin_packet_index,        tvb, 0,  4, ENC_BIG_ENDIAN);
 	proto_tree_add_item(adwin_tree, hf_adwin_request_no,          tvb, 4,  4, ENC_BIG_ENDIAN);
 	proto_tree_add_item(adwin_tree, hf_adwin_complete_packets,    tvb, 8,  4, ENC_BIG_ENDIAN);
 	proto_tree_add_item(adwin_debug_tree, hf_adwin_is_range,     tvb, 12,  4, ENC_BIG_ENDIAN);
 	proto_tree_add_item(adwin_debug_tree, hf_adwin_packet_start, tvb, 16,  4, ENC_BIG_ENDIAN);
 	proto_tree_add_item(adwin_debug_tree, hf_adwin_packet_end,   tvb, 20,  4, ENC_BIG_ENDIAN);

	is_range = tvb_get_ntohl(tvb, 12);
	packet_start = tvb_get_ntohl(tvb, 16);

	switch(is_range) {
	case 0:
		ti = proto_tree_add_uint_format_value(adwin_tree, hf_adwin_gdsh_status, tvb, 12, 4,
						is_range, "get single packet no %d", packet_start);
		break;
	case 1:
		packet_end = tvb_get_ntohl(tvb, 20);
		ti = proto_tree_add_uint_format_value(adwin_tree, hf_adwin_gdsh_status, tvb, 12, 4,
				    is_range, "get packets %d - %d",
				    packet_start, packet_end);
		break;
	case 2:
		ti = proto_tree_add_uint_format_value(adwin_tree, hf_adwin_gdsh_status, tvb, 12, 4,
				    is_range, "finished");
		break;
	default: /* should not happen */
		ti = proto_tree_add_uint_format_value(adwin_tree, hf_adwin_gdsh_status, tvb, 12, 4,
				    is_range, "unknown code %d", is_range);
	}
	proto_item_set_len(ti, 12);
	proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,       tvb, 24, 40, ENC_NA);
}

/* here we determine which type of packet is sent by looking at its
   size. That is safe since the main server application that processes
   these packets does it this way, too.

   Depending on the packet type, the appropriate dissector is
   called. */

static int
dissect_adwin_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti, *ti2;
	proto_tree *adwin_tree, *adwin_debug_tree;
	gchar *info_string;
	guint32 length;

	length = tvb_reported_length(tvb);

	/* First do some heuristics to see if this packet belongs to us */
	if(! (length == UDPH1_OLD_LENGTH
	      || length == UDPH1_NEW_LENGTH
	      || length == UDPR1_LENGTH
	      || length == UDPH2_LENGTH
	      || length == UDPR2_LENGTH
	      || length == UDPR3_LENGTH
	      || length == UDPR4_LENGTH
	      || length == GetDataSHPacket_LENGTH
	      || length == GetDataSHRequest_LENGTH))
		return(0);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADwin UDP");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_adwin, tvb, 0, -1, ENC_NA);
		adwin_tree = proto_item_add_subtree(ti, ett_adwin);

		ti2 = proto_tree_add_item(adwin_tree, proto_adwin, tvb, 0, -1, ENC_NA);
		adwin_debug_tree = proto_item_add_subtree(ti2, ett_adwin_debug);
		proto_item_set_text(ti2, "ADwin Debug information");
	} else {
		adwin_tree = NULL;
		adwin_debug_tree = NULL;
	}

	switch (length) {
	case UDPH1_OLD_LENGTH:
		dissect_UDPH1_old(tvb, pinfo, adwin_tree, adwin_debug_tree, &info_string);
		break;
	case UDPH1_NEW_LENGTH:
		dissect_UDPH1_new(tvb, pinfo, adwin_tree, adwin_debug_tree, &info_string);
		break;
	case UDPR1_LENGTH:
		dissect_UDPR1(tvb, pinfo, adwin_tree, adwin_debug_tree, &info_string);
		break;
	case UDPH2_LENGTH: /* to the best of my knowledge, this struct
			    * has never been used publically! */
		/* dissect_UDPH2(tvb, pinfo, adwin_tree, adwin_debug_tree); */
		info_string = wmem_strdup(wmem_packet_scope(), "UDPH2 - UNUSED");
		break;
	case UDPR2_LENGTH:
		dissect_UDPR2(tvb, pinfo, adwin_tree, adwin_debug_tree, &info_string);
		break;
	case UDPR3_LENGTH:
		dissect_UDPR3(tvb, pinfo, adwin_tree, adwin_debug_tree);
		info_string = wmem_strdup(wmem_packet_scope(), "UDPR3");
		break;
	case UDPR4_LENGTH:
		dissect_UDPR4(tvb, pinfo, adwin_tree, adwin_debug_tree, &info_string);
		break;
	case GetDataSHPacket_LENGTH:
		dissect_GDSHP(tvb, pinfo, adwin_tree, adwin_debug_tree);
		info_string = wmem_strdup(wmem_packet_scope(), "GDSHP");
		break;
	case GetDataSHRequest_LENGTH:
		dissect_GDSHR(tvb, pinfo, adwin_tree, adwin_debug_tree);
		info_string = wmem_strdup(wmem_packet_scope(), "GDSHR");
		break;
	default:
		info_string = wmem_strdup_printf(wmem_packet_scope(), "Unknown ADwin packet, length: %d", length);
		break;
	}

	col_add_str(pinfo->cinfo, COL_INFO, info_string);

	return (tvb_reported_length(tvb));
}

static guint
get_adwin_tcp_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	/*
	 * Return the length of the packet. (Doesn't include the length field itself)
	 */
	return tvb_get_ntohl(tvb, offset + 8) + 16;
}


static int
dissect_adwin_tcp_req(tvbuff_t *tvb,  packet_info *pinfo _U_, void* data _U_,
		      proto_tree *adwin_tree, proto_tree *adwin_debug_tree)
{
	guint32 seq_num, req_len;
	const gchar *info_string;
	adwin_transaction_t *transaction = NULL;
	proto_item *item;
	
	seq_num = tvb_get_ntohl(tvb, 4);
	req_len = tvb_get_ntohl(tvb, 8);
	
	adwin_request_response_handling(tvb, pinfo, adwin_tree, seq_num, ADWIN_REQUEST, &transaction);
	
	proto_tree_add_item(adwin_tree, hf_adwin_tcp_req_flag,   tvb,  0,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_tcp_req_count,  tvb,  4,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_tcp_req_len,    tvb,  8,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_instruction,    tvb, 12,  4, ENC_BIG_ENDIAN);

	if (! transaction) {
		return tvb_captured_length(tvb);
	}

	transaction->command = tvb_get_ntohl(tvb, 12);
	
	info_string = wmem_strdup_printf(wmem_packet_scope(), "%s: %s", "Request",
					 val_to_str_ext(transaction->command, &instruction_mapping_ext, "unknown instruction: %d"));

	switch (transaction->command) {
	case I_3PLUS1:
		transaction->command3p1 = tvb_get_ntohl(tvb, 16);
		transaction->additional_info1 = tvb_get_ntohl(tvb, 20);
		info_string = wmem_strdup_printf(wmem_packet_scope(), "%s: %s", info_string, // todo: info_string overlaps!!!
						 val_to_str_ext(transaction->command3p1, &instruction_3plus1_mapping_ext, "unknown 3+1 code: %d"));
		
		proto_tree_add_item(adwin_tree, hf_adwin_i3plus1,      tvb, 16,  4, ENC_BIG_ENDIAN);
		
		switch (transaction->command3p1) {
		case I_3P1_GET_PAR:
		case I_3P1_GET_DATA_STRING_SIZE:
		case I_3P1_GET_DATA_LENGTH:
		case I_3P1_GET_FIFO_EMPTY:
		case I_3P1_GET_FIFO_COUNT:	
		case I_3P1_START:
		case I_3P1_STOP:
		case I_3P1_CLEAR_DATA:
		case I_3P1_CLEAR_PROCESS:
		case I_3P1_CLEAR_FIFO:
		case I_3P1_ADC:
			/* only 1 useful value */
			proto_tree_add_item(adwin_debug_tree, hf_adwin_val1,    tvb, 16,  4, ENC_BIG_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 20, 12, ENC_NA);
			break;
		case I_3P1_GET_MEMORY_INFO:
		case I_3P1_GET_DETAILED_MEM_INFO:
		case I_3P1_GET_DIGIN:
		case I_3P1_GET_DIGOUT:
		case I_3P1_SET_DIGOUT:
		case I_3P1_DAC:
			/* only 2 useful value, both integer */
			proto_tree_add_item(adwin_tree, hf_adwin_val1,          tvb, 16,  4, ENC_BIG_ENDIAN);
			proto_tree_add_item(adwin_tree, hf_adwin_val2,          tvb, 20,  4, ENC_BIG_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 24,  8, ENC_NA);
			break;
		case I_3P1_SET_PAR:
			/* only 2 useful values, second may be integer or float */
			proto_tree_add_item(adwin_tree, hf_adwin_val1,          tvb, 16,  4, ENC_BIG_ENDIAN);
			proto_tree_add_item(adwin_tree, hf_adwin_val2,          tvb, 20,  4, ENC_BIG_ENDIAN);
			proto_tree_add_item(adwin_tree, hf_adwin_val2f,         tvb, 20,  4, ENC_BIG_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 24,  8, ENC_NA);
			break;
		default:
			/* printf("invalid 3p1 command found: %d\n", transaction->command3p1); */
			;
		}
		break;
	case I_BOOT:
	case I_LOAD_BIN_FILE:
		proto_tree_add_item(adwin_debug_tree, hf_adwin_blob,  tvb, 16,  req_len, ENC_NA);
		/* just binary blob */
		break;

	case I_GET_DATA:
	case I_GET_FIFO:
		proto_tree_add_item(adwin_tree, hf_adwin_data_no32,        tvb, 16,  4, ENC_BIG_ENDIAN);
		if (transaction->command == I_GET_DATA) {
			proto_tree_add_item(adwin_tree, hf_adwin_start_index, tvb, 20,  4, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(adwin_tree, hf_adwin_unused,   tvb, 20,  4, ENC_NA);
		}
		proto_tree_add_item(adwin_tree, hf_adwin_count,            tvb, 24,  4, ENC_BIG_ENDIAN);
		transaction->additional_info1 = tvb_get_ntohl(tvb, 16);
		transaction->additional_info2 = tvb_get_ntohl(tvb, 20);
		transaction->additional_info3 = tvb_get_ntohl(tvb, 24);
		break;
		
	case I_CREATE_DATA:
		proto_tree_add_item(adwin_tree, hf_adwin_data_no32,        tvb, 16,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_is_fifo,          tvb, 20,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_data_size,        tvb, 24,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_data_type,        tvb, 28,  4, ENC_BIG_ENDIAN);
		/* todo proto_tree_add_item(adwin_tree, hf_adwin_data_bank,        tvb, 32,  4, ENC_BIG_ENDIAN); */
		break;
		
	case I_GET_PAR_ALL:
		proto_tree_add_item(adwin_tree, hf_adwin_start_index,      tvb, 16,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_count,            tvb, 20,  4, ENC_BIG_ENDIAN);
		transaction->additional_info1 = tvb_get_ntohl(tvb, 16); 
		transaction->additional_info2 = tvb_get_ntohl(tvb, 20); 
		break;
		
	case I_GET_DATA_INFO:
	case I_GET_DATA_TYPE:
		proto_tree_add_item(adwin_tree, hf_adwin_data_no32,        tvb, 16,  4, ENC_BIG_ENDIAN);
		break;
		
	case I_SET_DATA:
	case I_SET_FIFO: {
		guint32 start_index, display_string_type, count, data_type, data_no;
		count = tvb_get_ntohl(tvb, 24);
		data_type = tvb_get_ntohl(tvb, 28);
		data_no = tvb_get_ntohl(tvb, 16);
		
		proto_tree_add_item(adwin_tree, hf_adwin_data_no32,        tvb, 16,  4, ENC_BIG_ENDIAN);
		if (transaction->command == I_SET_DATA) {
			proto_tree_add_item(adwin_tree, hf_adwin_start_index, tvb, 20,  4, ENC_BIG_ENDIAN);
			start_index = tvb_get_ntohl(tvb, 20);
			display_string_type = DISP_STR_DATA;
		} else {
			proto_tree_add_item(adwin_tree, hf_adwin_unused,   tvb, 20,  4, ENC_NA);
			start_index = 0;
			display_string_type = DISP_STR_FIFO;
		}
		proto_tree_add_item(adwin_tree, hf_adwin_count,            tvb, 24,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_data_type,        tvb, 28,  4, ENC_BIG_ENDIAN);

		dissect_data(tvb, pinfo, adwin_debug_tree, 32, data_no,
			     start_index, count, data_type, display_string_type);

		break;
	}
	case I_GET_WORKLOAD:
	case I_TEST_VERSION:
		/* no additional parameters */
		break;

	case I_AUTHENTICATE: {
		gchar* dll_version_s;
		gint32 dll_i;
		dll_i = tvb_get_ntohl(tvb, 16);
		dll_version_s = wmem_strdup_printf(wmem_packet_scope(), "%d.%d.%d",
						   dll_i / 1000000,
						   (dll_i - dll_i / 1000000 * 1000000) / 1000,
						   dll_i % 1000);
		proto_tree_add_string(adwin_debug_tree, hf_adwin_dll_version, tvb, 16, 4, dll_version_s);
		
		proto_tree_add_item(adwin_tree, hf_adwin_password,      tvb, 20, 12, ENC_ASCII|ENC_NA);
		proto_tree_add_item(adwin_tree, hf_adwin_timeout,       tvb, 32,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_timeout_size,  tvb, 36,  4, ENC_BIG_ENDIAN);
		break;
	}

	case I_GET_MEMORY:
		proto_tree_add_item(adwin_tree, hf_adwin_address,       tvb, 16,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_count,         tvb, 20,  4, ENC_BIG_ENDIAN);
		transaction->additional_info1 = tvb_get_ntohl(tvb, 16);
		transaction->additional_info2 = tvb_get_ntohl(tvb, 20);
		break;

	case I_GET_ARM_VERSION:
	case I_GET_DATA_SHIFTED_HANDSHAKE:
	case I_SET_DATA_LAST_STATUS:
	case I_GET_FIFO_RETRY:
	case I_SET_FIFO_RETRY:
	case I_GET_DATA_SMALL:
	case I_SET_DATA_N:
	case I_SET_FIFO_N:
	case I_GET_DATA_N:
	case I_GET_FIFO_N:
		item = proto_tree_add_string(adwin_debug_tree, hf_adwin_tcp_error,
					   tvb, 0, 0, "This instruction should not be used with TCP - Protocol error!");
		PROTO_ITEM_SET_GENERATED(item);
		break;
	}
	col_add_str(pinfo->cinfo, COL_INFO, info_string);
	
	return tvb_captured_length(tvb);
}

static int
dissect_adwin_tcp_resp(tvbuff_t *tvb,  packet_info *pinfo _U_, void* data _U_,
		      proto_tree *adwin_tree, proto_tree *adwin_debug_tree)
{
	guint32 seq_num, resp_len, status;
	const gchar *info_string;
	adwin_transaction_t *transaction = NULL;
	proto_item *item;
	
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADwin TCP");
	col_clear(pinfo->cinfo, COL_INFO);

	seq_num = tvb_get_ntohl(tvb, 4);
	resp_len = tvb_get_ntohl(tvb, 8);
	status = tvb_get_ntohl(tvb, 12);
	
	adwin_request_response_handling(tvb, pinfo, adwin_tree, seq_num, ADWIN_RESPONSE, &transaction);

	       
	proto_tree_add_item(adwin_tree, hf_adwin_tcp_resp_flag,  tvb,  0,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_tcp_req_count,  tvb,  4,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_tcp_req_len,    tvb,  8,  4, ENC_BIG_ENDIAN);
	proto_tree_add_item(adwin_tree, hf_adwin_status_header,  tvb, 12,  4, ENC_BIG_ENDIAN);
	
	info_string = try_val_to_str_ext(status, &error_code_mapping_ext);
	if (info_string) {
		info_string = wmem_strdup_printf(wmem_packet_scope(), "Response: %s", info_string);
	} else {
		info_string = wmem_strdup_printf(wmem_packet_scope(), "Undefined error code %d", status);
	}
	
	col_add_str(pinfo->cinfo, COL_INFO, info_string);

	if (! transaction) {
		return tvb_captured_length(tvb);
	}

	item = proto_tree_add_int(adwin_tree, hf_adwin_response_to_instruction,
					    tvb, 0, 0, transaction->command);
	PROTO_ITEM_SET_GENERATED(item);

	
	switch (transaction->command) {
	case I_3PLUS1:
		item = proto_tree_add_int(adwin_tree, hf_adwin_response_to_i3plus1,
					tvb, 0, 0, transaction->command3p1);
		PROTO_ITEM_SET_GENERATED(item);
		switch (transaction->command3p1) {
		case I_3P1_GET_PAR:
			/* only 1 useful value, maybe float or int */
			proto_tree_add_item(adwin_tree, hf_adwin_val1,          tvb, 16,  4, ENC_BIG_ENDIAN);
			proto_tree_add_item(adwin_tree, hf_adwin_val1f,         tvb, 16,  4, ENC_BIG_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 20, 12, ENC_NA);
			break;
		case I_3P1_GET_DATA_STRING_SIZE:
		case I_3P1_GET_MEMORY_INFO:
		case I_3P1_GET_DETAILED_MEM_INFO:
		case I_3P1_GET_DATA_LENGTH:
		case I_3P1_GET_FIFO_EMPTY:
		case I_3P1_GET_FIFO_COUNT:	
		case I_3P1_ADC:
		case I_3P1_GET_DIGIN:
		case I_3P1_GET_DIGOUT:
			/* only 1 useful value, always integer */
			proto_tree_add_item(adwin_tree, hf_adwin_val1,          tvb, 16,  4, ENC_BIG_ENDIAN);
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 20, 12, ENC_NA);
			break;
		case I_3P1_START:
		case I_3P1_STOP:
		case I_3P1_SET_PAR:
		case I_3P1_CLEAR_DATA:
		case I_3P1_CLEAR_PROCESS:
		case I_3P1_CLEAR_FIFO:
		case I_3P1_DAC:
		case I_3P1_SET_DIGOUT:
			/* no useful values (besides status in header) */
			proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 16, 16, ENC_NA);
			break;
		default:
			/* printf("invalid 3p1 command found: %d\n", transaction->command3p1); */
			;
		}
		break;

	case I_BOOT:
	case I_LOAD_BIN_FILE:
	case I_SET_DATA:
	case I_SET_FIFO:
	case I_CREATE_DATA:
		/* no info except of status in header */
		break;

	case I_GET_PAR_ALL: {
		guint32 display_string_type = DISP_STR_PAR, data_type = ADWIN_INTEGER, start_index = 0, count;
		count = transaction->additional_info2;
		if ((transaction->additional_info1 >   0) && (transaction->additional_info1 < 100)) {
			data_type = ADWIN_INTEGER;
			display_string_type = DISP_STR_PAR;
			start_index = transaction->additional_info1;
		}
		else if ((transaction->additional_info1 > 100) && (transaction->additional_info1 < 200)) {
			data_type = ADWIN_FLOAT;
			start_index = transaction->additional_info1 - 100;
			display_string_type = DISP_STR_FPAR;
		}
		else if ((transaction->additional_info1 > 200) && (transaction->additional_info1 < 300)) {
			data_type = ADWIN_DOUBLE;
			display_string_type = DISP_STR_FPAR_DOUBLE;
			start_index = transaction->additional_info1 - 200;
			/* for this type, the count must be devided by two (i.e., count is 4 for 2 doubles) */
			count /= 2;
		}
		dissect_data(tvb, pinfo, adwin_debug_tree, 16, 0, start_index, count, data_type, display_string_type);
		break;
	}
	case I_GET_WORKLOAD:
		proto_tree_add_item(adwin_tree, hf_adwin_val1,          tvb, 16,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_val2,          tvb, 20,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_val3,          tvb, 24,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_unused,        tvb, 28,  4, ENC_NA);
		break;
		
	case I_GET_DATA_INFO:
		proto_tree_add_item(adwin_tree, hf_adwin_data_type,     tvb, 16,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_data_size,     tvb, 20,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_is_fifo,       tvb, 24,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_fifo_full,     tvb, 28,  4, ENC_BIG_ENDIAN);
		break;
		
	case I_GET_DATA_TYPE:
		proto_tree_add_item(adwin_tree, hf_adwin_data_type,     tvb, 16,  4, ENC_BIG_ENDIAN);
		break;

	case I_GET_FIFO:
	case I_GET_DATA: {
		guint32 display_str_type, data_type;
		data_type = tvb_get_ntohl(tvb, 16);
		proto_tree_add_item(adwin_tree, hf_adwin_data_type,      tvb, 16,  4, ENC_BIG_ENDIAN);
		
		proto_tree_add_item(adwin_tree, hf_adwin_data_size,      tvb, 20,  4, ENC_BIG_ENDIAN);
		if (transaction->command == I_GET_DATA) {
			proto_tree_add_item(adwin_tree, hf_adwin_unused,         tvb, 24,  4, ENC_NA);
			display_str_type = DISP_STR_DATA;
		} else {
			proto_tree_add_item(adwin_tree, hf_adwin_fifo_full,    tvb, 24,  4, ENC_BIG_ENDIAN);
			display_str_type = DISP_STR_FIFO;
		}

		dissect_data(tvb, pinfo, adwin_debug_tree, 28, transaction->additional_info1,
			     transaction->additional_info2, transaction->additional_info3, data_type,
			     display_str_type);
		break;
	}		
	case I_SET_DATA_N:
	case I_SET_FIFO_N:
	case I_GET_DATA_N:
	case I_GET_FIFO_N:
	case I_GET_DATA_SHIFTED_HANDSHAKE:
	case I_SET_DATA_LAST_STATUS:
	case I_GET_FIFO_RETRY:
	case I_SET_FIFO_RETRY:
	case I_GET_DATA_SMALL:
	case I_GET_ARM_VERSION:
		item = proto_tree_add_string(adwin_debug_tree, hf_adwin_tcp_error,
					   tvb, 0, 0, "This instruction should not be used with TCP - Protocol error!");
		PROTO_ITEM_SET_GENERATED(item);
		break;
		
	case I_TEST_VERSION:
		/* no really useful info... */
		proto_tree_add_item(adwin_debug_tree, hf_adwin_unused,  tvb, 16,  16, ENC_NA);
		break;
		
	case I_AUTHENTICATE:
		proto_tree_add_item(adwin_tree, hf_adwin_processor,     tvb, 16,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_conn_count,    tvb, 20,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_firmware_vers, tvb, 24,  4, ENC_BIG_ENDIAN);
		proto_tree_add_item(adwin_tree, hf_adwin_firmware_vers_beta, tvb, 28,  4, ENC_BIG_ENDIAN);
		break;
		
	case I_GET_MEMORY: {
		dissect_data(tvb, pinfo, adwin_debug_tree, 16, 0,
			     transaction->additional_info1, transaction->additional_info2, ADWIN_INTEGER, DISP_STR_MEMORY);
		proto_tree_add_item(adwin_tree, hf_adwin_status_final,   tvb, 16 + resp_len - 4,  4, ENC_BIG_ENDIAN);
		break;
	}}
		
	return tvb_captured_length(tvb);
}

static int
dissect_adwin_tcp_req_resp(tvbuff_t *tvb,  packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	proto_item *ti, *ti2;
	proto_tree *adwin_tree, *adwin_debug_tree;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADwin TCP");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_adwin, tvb, 0, -1, ENC_NA);
		adwin_tree = proto_item_add_subtree(ti, ett_adwin);
		
		ti2 = proto_tree_add_item(adwin_tree, proto_adwin, tvb, 0, -1, ENC_NA);
		adwin_debug_tree = proto_item_add_subtree(ti2, ett_adwin_debug);
		proto_item_set_text(ti2, "ADwin Debug information");
	} else {
		adwin_tree = NULL;
		adwin_debug_tree = NULL;
	}

	switch (tvb_get_ntohl(tvb, 0)) {
	case ADWIN_TCP_MAGIC_FLAG_REQUEST:
		dissect_adwin_tcp_req(tvb, pinfo, data, adwin_tree, adwin_debug_tree);
		break;
	case ADWIN_TCP_MAGIC_FLAG_RESPONSE:
		dissect_adwin_tcp_resp(tvb, pinfo, data, adwin_tree, adwin_debug_tree);
		break;
	default:
		/* printf("invalid flag\n"); */
		return 0;
	}

	return tvb_captured_length(tvb);
}

static int
dissect_adwin_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if(!(pinfo->srcport == global_adwin_port || pinfo->destport == global_adwin_port))
		return 0;
	
	tcp_dissect_pdus(tvb, pinfo, tree, 1, 16, get_adwin_tcp_len, dissect_adwin_tcp_req_resp, NULL);
	
	return (tvb_reported_length(tvb));
}

void
proto_reg_handoff_adwin(void)
{
	static int adwin_prefs_initialized = FALSE;
	static dissector_handle_t adwin_handle_udp, adwin_handle_tcp;

	if (! adwin_prefs_initialized) {
		adwin_handle_udp = create_dissector_handle(dissect_adwin_udp, proto_adwin);
		adwin_handle_tcp = create_dissector_handle(dissect_adwin_tcp, proto_adwin);
		data_handle = find_dissector("data");
		adwin_prefs_initialized = TRUE;
	} else {
		dissector_delete_uint("udp.port", global_adwin_port, adwin_handle_udp);
		dissector_delete_uint("tcp.port", global_adwin_port, adwin_handle_tcp);
	}

	dissector_add_uint("udp.port", global_adwin_port, adwin_handle_udp);
	dissector_add_uint("tcp.port", global_adwin_port, adwin_handle_tcp);
}

void
proto_register_adwin(void)
{
	static hf_register_info hf[] = {
		{ &hf_adwin_address,
		  { "memory address", "adwin.address",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Memory address to read on DSP", HFILL }
		},
		{ &hf_adwin_armVersion,
		  { "Get ARM Version", "adwin.armVersion",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_binfilesize,
		  { "File size", "adwin.binfilesize",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Size of binary file", HFILL }
		},
		{ &hf_adwin_blob,
		  { "Binary information", "adwin.blob",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_blocksize,
		  { "Blocksize", "adwin.blocksize",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Maximum number of unacknowledged packets", HFILL }
		},
		{ &hf_adwin_complete_packets,
		  { "Complete packets", "adwin.complete_packets",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Highest sequential package number", HFILL }
		},
		{ &hf_adwin_conn_count,
		  { "TCP connection count", "adwin.connection_count",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Number of active TCP connections, including the current connection.", HFILL }
		},
		{ &hf_adwin_count,
		  { "Count", "adwin.count",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Number of longs", HFILL }
		},
		{ &hf_adwin_data,
		  { "Data", "adwin.data",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_int8,
		  { "Data element int8", "adwin.data_int8",
		    FT_INT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_int8_hex,
		  { "Data element int8 (hex notation)", "adwin.data_int8_hex",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_int16,
		  { "Data element int16", "adwin.data_int16",
		    FT_INT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_int16_hex,
		  { "Data element int16 (hex notation)", "adwin.data_int16_hex",
		    FT_UINT16, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_int32,
		  { "Data element int32", "adwin.data_int32",
 		    FT_INT32, BASE_DEC, NULL, 0x0,
 		    NULL, HFILL }
 		},
		{ &hf_adwin_data_int32_hex,
		  { "Data element int32 (hex notation)", "adwin.data_int32_hex",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_int64,
		  { "Data element int64", "adwin.data_int64",
		    FT_INT64, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_int64_hex,
		  { "Data element int64 (hex notation)", "adwin.data_int64_hex",
		    FT_UINT64, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_double,
		  { "Data element double", "adwin.data_double",
		    FT_DOUBLE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_float,
		  { "Data element float", "adwin.data_float",
		    FT_FLOAT, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_string,
		  { "Data element string", "adwin.data_string",
		    FT_STRING, BASE_NONE, NULL, 0x0,
 		    NULL, HFILL }
 		},
		{ &hf_adwin_data_no16,
		  { "Data No. (16bit)", "adwin.data_no16",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_no32,
		  { "Data No. (32bit)", "adwin.data_no32",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_size,
		  { "Data size", "adwin.data_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_type,
		  { "Data type", "adwin.data_type",
		    FT_UINT32, BASE_DEC|BASE_EXT_STRING, &data_type_mapping_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_data_packet_index,
		  { "Data packet index", "adwin.data_packet_index",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_dll_version,
		  { "DLL Version", "adwin.dll_version",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_fifo_full,
		  { "Fifo full count", "adwin.fifo_full",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_fifo_no16,
		  { "FiFo No. (16bit)", "adwin.fifo_no",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_fifo_no32,
		  { "FiFo No. (32bit)", "adwin.fifo_no",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_firmware_vers,
		  { "Firmware version", "adwin.firmware_version",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_firmware_vers_beta,
		  { "Firmware version (beta)", "adwin.firmware_version_beta",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_instruction,
		  { "Instruction", "adwin.instruction",
		    FT_UINT32, BASE_DEC|BASE_EXT_STRING, &instruction_mapping_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_is_range,
		  { "packets are a range", "adwin.is_range",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_is_fifo,
		  { "Is fifo", "adwin.is_fifo",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_i3plus1,
		  { "3+1 Instruction", "adwin.i3plus1",
		    FT_UINT32, BASE_DEC|BASE_EXT_STRING, &instruction_3plus1_mapping_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_link_addr,
		  { "Link address", "adwin.link_addr",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Link address (TCP/IP Server only)", HFILL }
		},
		{ &hf_adwin_mem_type,
		  { "Memory type", "adwin.mem_type",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_memsize,
		  { "Memory size", "adwin.memsize",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_osys,
		  { "Operating system", "adwin.osys",
		    FT_UINT32, BASE_DEC|BASE_EXT_STRING, &osys_mapping_ext, 0x0,
		    "Operating system / environment", HFILL }
		},
		{ &hf_adwin_packet_end,
		  { "End packet", "adwin.packet_end",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "GDSH: End Packet", HFILL }
		},
		{ &hf_adwin_gdsh_status,
		  { "GDSH status", "adwin.gdsh_status",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_packet_index,
		  { "Packet index", "adwin.packet_index",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_packet_no,
		  { "Packet No.", "adwin.packet_no",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_packet_start,
		  { "Starting packet", "adwin.packet_start",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "GDSH: Starting Packet", HFILL }
		},
		{ &hf_adwin_packet_type,
		  { "Packet type", "adwin.packet_type",
		    FT_INT32, BASE_DEC|BASE_EXT_STRING, &packet_type_mapping_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_parameter,
		  { "Parameter", "adwin.parameter",
		    FT_UINT32, BASE_DEC|BASE_EXT_STRING, &parameter_mapping_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_password,
		  { "Password", "adwin.password",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Password for ADwin system", HFILL }
		},
		{ &hf_adwin_process_no,
		  { "Process No.", "adwin.process_no",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_processor,
		  { "Processor", "adwin.processor",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_response_in,
		  { "Response In", "adwin.response_in",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "The response to this ADwin request is in this frame", HFILL }
		},
		{ &hf_adwin_response_to,
		  { "Request In", "adwin.response_to",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "This is a response to the ADwin request in this frame", HFILL }
		},
		{ &hf_adwin_response_time,
		  { "Response time", "adwin.response_time",
		    FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		    "The time between the Request and the Reply", HFILL }
		},
		{ &hf_adwin_response_to_i3plus1,
		  { "Response to 3+1 Instruction", "adwin.response_to_i3plus1",
		    FT_INT32, BASE_DEC|BASE_EXT_STRING, &instruction_3plus1_mapping_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_response_to_instruction,
		  { "Response to instruction", "adwin.response_to_instruction",
		    FT_INT32, BASE_DEC|BASE_EXT_STRING, &instruction_mapping_ext, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_retry_packet_index,
		  { "Retry packet index", "adwin.retry_packet_index",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_request_no,
		  { "Request Number", "adwin.request_no",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Request number index", HFILL }
		},
		{ &hf_adwin_start_index,
		  { "Start index", "adwin.start_index",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_status_header,
		  { "Status in header", "adwin.status_header",
		    FT_INT32, BASE_DEC|BASE_EXT_STRING, &error_code_mapping_ext, 0x0,
		    "Status information explicitly for this packet.", HFILL }
		},
		{ &hf_adwin_status_final,
		  { "Status after data transmission", "adwin.status_final",
		    FT_INT32, BASE_DEC|BASE_EXT_STRING, &error_code_mapping_ext, 0x0,
		    "Status information for a preceding data transfer.", HFILL } /*  */
		},
		{ &hf_adwin_timeout,
		  { "Timeout", "adwin.timeout",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Timeout in ms", HFILL }
		},
		{ &hf_adwin_timeout_size,
		  { "Data size which is relevant for timeout", "adwin.timeout_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Size of data transfer in bytesthat the timeout applies to.", HFILL }
		},
		{ &hf_adwin_unused,
		  { "Unused", "adwin.unused",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_adwin_val1,
		  { "Value 1 (as int)", "adwin.val1",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Generic return value 1 interpreted as integer (correct interpretation depends on request).", HFILL }
		},
		{ &hf_adwin_val1f,
		  { "Value 1 (as float)", "adwin.val1f",
		    FT_FLOAT, BASE_NONE, NULL, 0x0,
		    "Generic return value 1 interpreted as float (correct interpretation depends on request).", HFILL }
		},
		{ &hf_adwin_val2,
		  { "Value 2", "adwin.val2",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Generic return value 2 intrepreted as integer (correct interpretation depends on request).", HFILL }
		},
		{ &hf_adwin_val2f,
		  { "Value 2 (as float)", "adwin.val2f",
		    FT_FLOAT, BASE_NONE, NULL, 0x0,
		    "Generic return value 2 interpreted as float (correct(interpretation depends on request).", HFILL }
		},
		{ &hf_adwin_val3,
		  { "Value 3", "adwin.val3",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Generic return value 3 (interpretation depends on request).", HFILL }
		},
		{ &hf_adwin_val4,
		  { "Value 4", "adwin.val4",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    "Generic return value 4 (interpretation depends on request).", HFILL }
		},
		{ &hf_adwin_tcp_req_flag,
		  { "TCP request magic flag", "adwin.tcp_req_magic_flag",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "ADwin TCP request magic flag.", HFILL }
		},
		{ &hf_adwin_tcp_resp_flag,
		  { "TCP response magic flag", "adwin.tcp_resp_magic_flag",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "ADwin TCP response magic flag.", HFILL }
		},
		{ &hf_adwin_tcp_req_len,
		  { "TCP request length", "adwin.tcp_req_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "ADwin TCP request length.", HFILL }
		},
		{ &hf_adwin_tcp_req_count,
		  { "TCP request count", "adwin.tcp_req_count",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "ADwin TCP request count.", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_adwin,
		&ett_adwin_debug,
	};
	module_t *adwin_module;

	/* Register the protocol name and description */
	proto_adwin = proto_register_protocol("ADwin communication protocol",
					      "ADwin", "adwin");

	/* Required function calls to register the header fields and
	   subtrees used */
	proto_register_field_array(proto_adwin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register our configuration options for ADwin, particularly
	   our port */
	adwin_module = prefs_register_protocol(proto_adwin, proto_reg_handoff_adwin);

	prefs_register_uint_preference(adwin_module, "udp.port", "ADwin TCP/UDP Port",
				       "Set the TCP/UDP port for ADwin packets (if other"
				       " than the default of 6543)",
				       10, &global_adwin_port);

	prefs_register_bool_preference(adwin_module, "dissect_data",
				       "Dissect Data sections",
				       "Specify if the Data sections of packets "
				       "should be dissected or not",
				       &global_adwin_dissect_data);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
