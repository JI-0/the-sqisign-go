#ifndef TEST_BASIS_H
#define TEST_BASIS_H
#include "fp2.h"
#if 0
#elif 8*DIGIT_LEN == 16
const const fp2_t xPA = {{0x28ee, 0xb360, 0xfd6a, 0xdb68, 0x7e6d, 0x2b24, 0xcbd2, 0xb67e, 0xf4a0, 0x10bf, 0xdb4a, 0x3d, 0xeabc, 0x1ed4, 0xcf04, 0x31ec, 0x1615, 0x3dbd, 0xb74e, 0x6c93, 0xc342, 0x8a69, 0xe18a, 0xec}, {0x3b4e, 0xd53a, 0x22e0, 0x3ac9, 0x4daf, 0x5856, 0xc421, 0xaaa4, 0x1fce, 0x4b83, 0xd874, 0x1359, 0x3a70, 0xa89, 0xb5f5, 0x6f1e, 0x83e, 0xdf9f, 0x2fff, 0x290b, 0x36bb, 0xe486, 0x212f, 0x56}};
const const fp2_t xPB = {{0x18e1, 0x8371, 0xfbf6, 0x4668, 0xf86b, 0xde4e, 0x541c, 0xe3f7, 0x62fa, 0x9df3, 0xf470, 0x6222, 0x3eeb, 0xc27d, 0x4e39, 0xfff0, 0x3ac4, 0xd78c, 0x899e, 0x950a, 0x5991, 0xdae4, 0xb141, 0x325}, {0x75d7, 0x23c9, 0x2b8, 0xdcd3, 0xe655, 0x892d, 0x4513, 0x52a7, 0x7e45, 0x9938, 0x8b35, 0x7169, 0x95b1, 0x17eb, 0x4680, 0x190b, 0x6ff3, 0x978b, 0x5211, 0x8d1e, 0x6f88, 0x16c3, 0xc085, 0x29d}};
const const fp2_t xP2 = {{0xd255, 0x34b7, 0x3551, 0x22e6, 0x8dc, 0x597d, 0xf4f4, 0xa7f7, 0x8eec, 0xd588, 0xe50, 0xb8eb, 0x72ba, 0xc7f, 0xa84e, 0xed36, 0xf28e, 0x46f3, 0x1c0b, 0xb6ed, 0xd1b8, 0x62f4, 0x153a, 0x282}, {0xa787, 0x4410, 0xfea7, 0xd57e, 0xd250, 0x9d71, 0x60d6, 0xea44, 0x7a46, 0x9339, 0xad41, 0xb3d9, 0xa081, 0x3ff1, 0xb5b9, 0x3124, 0x3709, 0xc82d, 0xb0, 0x45a8, 0x3c61, 0xe135, 0xe60, 0x24b}};
const const fp2_t xP3 = {{0xabd4, 0xf3a2, 0xd0f7, 0x6c9c, 0x2667, 0x61db, 0x151f, 0xd245, 0x8cdc, 0xfe46, 0xd982, 0xafd, 0xd95d, 0x9aab, 0x1b33, 0x3b60, 0x8421, 0x4847, 0xdafa, 0x2e97, 0x2b7b, 0xa829, 0x798, 0x367}, {0x14f6, 0x25a1, 0x6e98, 0x1044, 0xd6c, 0x765b, 0xa272, 0x49b7, 0x1c39, 0x4729, 0xdf9f, 0xb907, 0xba6d, 0xeb97, 0x71a2, 0xfe17, 0x8038, 0xced8, 0xf215, 0xad85, 0x7156, 0xe70, 0xafd3, 0x1ba}};
const const fp2_t xQA = {{0xfc70, 0x2398, 0x8814, 0xd64d, 0xb8ad, 0xb175, 0x91e2, 0x8cd7, 0x5996, 0x94e6, 0x16a5, 0x8cf8, 0xbc3e, 0x4f4b, 0x1553, 0xdc, 0xb695, 0xca9c, 0x5f0f, 0x2ebd, 0x35e3, 0x6406, 0x7728, 0x267}, {0xf154, 0xdd48, 0x9814, 0x8e85, 0x2e17, 0xd3fb, 0x48d3, 0x400b, 0x1a9, 0xbbc4, 0x5059, 0x9e31, 0x4034, 0x5c0a, 0x4fc8, 0x26c2, 0xcc0e, 0xe3a1, 0xf2ad, 0x2095, 0x4796, 0x4379, 0x9dae, 0x78}};
const const fp2_t xQB = {{0x8c34, 0x6c33, 0xd365, 0x29eb, 0x22cb, 0x705b, 0xf65c, 0x2bfc, 0x4ae, 0xfff8, 0x5916, 0xc34d, 0xf777, 0x7596, 0xa557, 0x936f, 0x14b1, 0xa823, 0x262e, 0x88bc, 0xf63f, 0xc5eb, 0x841b, 0x3cb}, {0x914c, 0x30a1, 0xd5a5, 0x1cd8, 0xe567, 0x4b7f, 0xdc46, 0xaa47, 0x2302, 0x20a1, 0xcfba, 0xb2f6, 0x764a, 0x8ed5, 0x2a7f, 0xbdec, 0x42f7, 0xb903, 0xcaff, 0x8d8, 0x23a0, 0xe260, 0x600d, 0x2bc}};
const const fp2_t xQ2 = {{0xde7f, 0xd274, 0xf8f9, 0x17d, 0xc8aa, 0xe83e, 0x32cc, 0x3516, 0xaf7e, 0xae8d, 0x19de, 0x56e0, 0xa3b, 0xc182, 0x5b5d, 0x3da3, 0x75b1, 0x759b, 0xde7d, 0xbb60, 0xa4d9, 0xd5d0, 0x1949, 0x2e8}, {0x5804, 0x225c, 0xe85f, 0xa4ef, 0xb4f8, 0x2e16, 0x9fc3, 0x9cbd, 0xbbc, 0xd7c2, 0x541e, 0xa8be, 0xd902, 0xd571, 0x875b, 0xe057, 0x21ff, 0x3dab, 0xbaf0, 0x35f5, 0x9545, 0x8469, 0x3d27, 0x349}};
const const fp2_t xQ3 = {{0xa8e9, 0x950f, 0x26ec, 0x6072, 0xafd, 0x29c8, 0x9c0c, 0x1e2e, 0xa2c0, 0x9cf6, 0x936b, 0xa031, 0xa4a7, 0xc532, 0xc851, 0x7315, 0x52f1, 0x81b0, 0x288e, 0x2d60, 0xa243, 0x9523, 0x1ee6, 0xe4}, {0xb302, 0x7f7a, 0x9026, 0x5747, 0x394c, 0x3c3a, 0x2b25, 0xce89, 0xd34, 0xc2ec, 0x137f, 0xb5b3, 0x32a5, 0x9cea, 0x2df4, 0x7f54, 0xe6c6, 0x5b05, 0x2d3e, 0x33f7, 0xf6c6, 0xfbb1, 0x6516, 0x39c}};
const const fp2_t xPQA = {{0xff9e, 0x4e95, 0x5c81, 0x55c, 0xf66d, 0x2d08, 0xa750, 0x624a, 0xb1b5, 0x3369, 0x96a4, 0xfaef, 0x1da, 0x3866, 0x164a, 0x6bd0, 0x4884, 0xbcab, 0x4ecc, 0xc462, 0x8312, 0x321, 0x54ec, 0x101}, {0x4beb, 0x5f4e, 0xbe9e, 0x4fbf, 0xa298, 0xc9a7, 0x132c, 0x1392, 0x694c, 0x2df2, 0xe290, 0x87be, 0x836c, 0xc82c, 0xded, 0x2fd7, 0x4330, 0x33ea, 0xa668, 0xb969, 0xc86e, 0x10ea, 0x80d6, 0xac}};
const const fp2_t xPQB = {{0xec0b, 0x1f16, 0x90e0, 0xef, 0xc8ca, 0x14cd, 0x2300, 0xbe3b, 0x7c6a, 0x9100, 0x68a, 0x11d8, 0xeb46, 0xa468, 0xfc7, 0xef6, 0xeacc, 0x4394, 0x6eb8, 0x6ebe, 0xc97e, 0xb9c, 0x7d0c, 0xb2}, {0xc728, 0x4ffb, 0x4d14, 0xfb4, 0x2fb0, 0xbb63, 0xd8aa, 0x35fe, 0x4c4c, 0x3ad4, 0xdf0, 0xbce8, 0xe79a, 0xd612, 0x73d6, 0x94e9, 0x5d91, 0x8836, 0x5599, 0xf90b, 0xf701, 0x5fce, 0xb392, 0x1d8}};
const const fp2_t xPQ2 = {{0x20f8, 0x3f44, 0x8fba, 0xb37f, 0x6df, 0xb037, 0xf1ac, 0x8d48, 0xfdbc, 0x530f, 0x4860, 0x5f5d, 0xe98e, 0x7f4, 0xcb73, 0x3346, 0x87ef, 0x1d81, 0x3a15, 0xebbd, 0x52b0, 0x4b5f, 0x3e66, 0x14e}, {0x6795, 0xf465, 0x1da8, 0xdab9, 0xac88, 0x108c, 0xf3c3, 0xdbdc, 0xde21, 0xa27b, 0x467c, 0x272d, 0x3cf0, 0x9dc7, 0xd2cd, 0x147e, 0x4d50, 0xfd5d, 0x1707, 0x6742, 0x9bda, 0xaa55, 0xf704, 0x1c9}};
const const fp2_t xPQ3 = {{0x7e2c, 0x6d2d, 0x2523, 0xcc52, 0xdfd3, 0x5811, 0xc045, 0x5c1c, 0x8e01, 0x8266, 0xb107, 0xd863, 0x3bf9, 0xc45b, 0x32a, 0x5e6d, 0x202b, 0x95d6, 0xdd5d, 0xcab4, 0x68a3, 0x9dc5, 0x35aa, 0x368}, {0x1038, 0x559d, 0xf514, 0x372, 0x597e, 0xd7d5, 0x4a, 0x2064, 0x462c, 0xe96c, 0xd0, 0xdcfd, 0x31b6, 0xef32, 0x5de9, 0x13a9, 0x21f7, 0xa9a, 0x577b, 0x9302, 0xaff4, 0x3629, 0x1507, 0x7}};
#elif 8*DIGIT_LEN == 32
const const fp2_t xPA = {{0xb36028ee, 0xdb68fd6a, 0x2b247e6d, 0xb67ecbd2, 0x10bff4a0, 0x3ddb4a, 0x1ed4eabc, 0x31eccf04, 0x3dbd1615, 0x6c93b74e, 0x8a69c342, 0xece18a}, {0xd53a3b4e, 0x3ac922e0, 0x58564daf, 0xaaa4c421, 0x4b831fce, 0x1359d874, 0xa893a70, 0x6f1eb5f5, 0xdf9f083e, 0x290b2fff, 0xe48636bb, 0x56212f}};
const const fp2_t xPB = {{0x837118e1, 0x4668fbf6, 0xde4ef86b, 0xe3f7541c, 0x9df362fa, 0x6222f470, 0xc27d3eeb, 0xfff04e39, 0xd78c3ac4, 0x950a899e, 0xdae45991, 0x325b141}, {0x23c975d7, 0xdcd302b8, 0x892de655, 0x52a74513, 0x99387e45, 0x71698b35, 0x17eb95b1, 0x190b4680, 0x978b6ff3, 0x8d1e5211, 0x16c36f88, 0x29dc085}};
const const fp2_t xP2 = {{0x34b7d255, 0x22e63551, 0x597d08dc, 0xa7f7f4f4, 0xd5888eec, 0xb8eb0e50, 0xc7f72ba, 0xed36a84e, 0x46f3f28e, 0xb6ed1c0b, 0x62f4d1b8, 0x282153a}, {0x4410a787, 0xd57efea7, 0x9d71d250, 0xea4460d6, 0x93397a46, 0xb3d9ad41, 0x3ff1a081, 0x3124b5b9, 0xc82d3709, 0x45a800b0, 0xe1353c61, 0x24b0e60}};
const const fp2_t xP3 = {{0xf3a2abd4, 0x6c9cd0f7, 0x61db2667, 0xd245151f, 0xfe468cdc, 0xafdd982, 0x9aabd95d, 0x3b601b33, 0x48478421, 0x2e97dafa, 0xa8292b7b, 0x3670798}, {0x25a114f6, 0x10446e98, 0x765b0d6c, 0x49b7a272, 0x47291c39, 0xb907df9f, 0xeb97ba6d, 0xfe1771a2, 0xced88038, 0xad85f215, 0xe707156, 0x1baafd3}};
const const fp2_t xQA = {{0x2398fc70, 0xd64d8814, 0xb175b8ad, 0x8cd791e2, 0x94e65996, 0x8cf816a5, 0x4f4bbc3e, 0xdc1553, 0xca9cb695, 0x2ebd5f0f, 0x640635e3, 0x2677728}, {0xdd48f154, 0x8e859814, 0xd3fb2e17, 0x400b48d3, 0xbbc401a9, 0x9e315059, 0x5c0a4034, 0x26c24fc8, 0xe3a1cc0e, 0x2095f2ad, 0x43794796, 0x789dae}};
const const fp2_t xQB = {{0x6c338c34, 0x29ebd365, 0x705b22cb, 0x2bfcf65c, 0xfff804ae, 0xc34d5916, 0x7596f777, 0x936fa557, 0xa82314b1, 0x88bc262e, 0xc5ebf63f, 0x3cb841b}, {0x30a1914c, 0x1cd8d5a5, 0x4b7fe567, 0xaa47dc46, 0x20a12302, 0xb2f6cfba, 0x8ed5764a, 0xbdec2a7f, 0xb90342f7, 0x8d8caff, 0xe26023a0, 0x2bc600d}};
const const fp2_t xQ2 = {{0xd274de7f, 0x17df8f9, 0xe83ec8aa, 0x351632cc, 0xae8daf7e, 0x56e019de, 0xc1820a3b, 0x3da35b5d, 0x759b75b1, 0xbb60de7d, 0xd5d0a4d9, 0x2e81949}, {0x225c5804, 0xa4efe85f, 0x2e16b4f8, 0x9cbd9fc3, 0xd7c20bbc, 0xa8be541e, 0xd571d902, 0xe057875b, 0x3dab21ff, 0x35f5baf0, 0x84699545, 0x3493d27}};
const const fp2_t xQ3 = {{0x950fa8e9, 0x607226ec, 0x29c80afd, 0x1e2e9c0c, 0x9cf6a2c0, 0xa031936b, 0xc532a4a7, 0x7315c851, 0x81b052f1, 0x2d60288e, 0x9523a243, 0xe41ee6}, {0x7f7ab302, 0x57479026, 0x3c3a394c, 0xce892b25, 0xc2ec0d34, 0xb5b3137f, 0x9cea32a5, 0x7f542df4, 0x5b05e6c6, 0x33f72d3e, 0xfbb1f6c6, 0x39c6516}};
const const fp2_t xPQA = {{0x4e95ff9e, 0x55c5c81, 0x2d08f66d, 0x624aa750, 0x3369b1b5, 0xfaef96a4, 0x386601da, 0x6bd0164a, 0xbcab4884, 0xc4624ecc, 0x3218312, 0x10154ec}, {0x5f4e4beb, 0x4fbfbe9e, 0xc9a7a298, 0x1392132c, 0x2df2694c, 0x87bee290, 0xc82c836c, 0x2fd70ded, 0x33ea4330, 0xb969a668, 0x10eac86e, 0xac80d6}};
const const fp2_t xPQB = {{0x1f16ec0b, 0xef90e0, 0x14cdc8ca, 0xbe3b2300, 0x91007c6a, 0x11d8068a, 0xa468eb46, 0xef60fc7, 0x4394eacc, 0x6ebe6eb8, 0xb9cc97e, 0xb27d0c}, {0x4ffbc728, 0xfb44d14, 0xbb632fb0, 0x35fed8aa, 0x3ad44c4c, 0xbce80df0, 0xd612e79a, 0x94e973d6, 0x88365d91, 0xf90b5599, 0x5fcef701, 0x1d8b392}};
const const fp2_t xPQ2 = {{0x3f4420f8, 0xb37f8fba, 0xb03706df, 0x8d48f1ac, 0x530ffdbc, 0x5f5d4860, 0x7f4e98e, 0x3346cb73, 0x1d8187ef, 0xebbd3a15, 0x4b5f52b0, 0x14e3e66}, {0xf4656795, 0xdab91da8, 0x108cac88, 0xdbdcf3c3, 0xa27bde21, 0x272d467c, 0x9dc73cf0, 0x147ed2cd, 0xfd5d4d50, 0x67421707, 0xaa559bda, 0x1c9f704}};
const const fp2_t xPQ3 = {{0x6d2d7e2c, 0xcc522523, 0x5811dfd3, 0x5c1cc045, 0x82668e01, 0xd863b107, 0xc45b3bf9, 0x5e6d032a, 0x95d6202b, 0xcab4dd5d, 0x9dc568a3, 0x36835aa}, {0x559d1038, 0x372f514, 0xd7d5597e, 0x2064004a, 0xe96c462c, 0xdcfd00d0, 0xef3231b6, 0x13a95de9, 0xa9a21f7, 0x9302577b, 0x3629aff4, 0x71507}};
#elif 8*DIGIT_LEN == 64
const const fp2_t xPA = {{0xdb68fd6ab36028ee, 0xb67ecbd22b247e6d, 0x3ddb4a10bff4a0, 0x31eccf041ed4eabc, 0x6c93b74e3dbd1615, 0xece18a8a69c342}, {0x3ac922e0d53a3b4e, 0xaaa4c42158564daf, 0x1359d8744b831fce, 0x6f1eb5f50a893a70, 0x290b2fffdf9f083e, 0x56212fe48636bb}};
const const fp2_t xPB = {{0x4668fbf6837118e1, 0xe3f7541cde4ef86b, 0x6222f4709df362fa, 0xfff04e39c27d3eeb, 0x950a899ed78c3ac4, 0x325b141dae45991}, {0xdcd302b823c975d7, 0x52a74513892de655, 0x71698b3599387e45, 0x190b468017eb95b1, 0x8d1e5211978b6ff3, 0x29dc08516c36f88}};
const const fp2_t xP2 = {{0x22e6355134b7d255, 0xa7f7f4f4597d08dc, 0xb8eb0e50d5888eec, 0xed36a84e0c7f72ba, 0xb6ed1c0b46f3f28e, 0x282153a62f4d1b8}, {0xd57efea74410a787, 0xea4460d69d71d250, 0xb3d9ad4193397a46, 0x3124b5b93ff1a081, 0x45a800b0c82d3709, 0x24b0e60e1353c61}};
const const fp2_t xP3 = {{0x6c9cd0f7f3a2abd4, 0xd245151f61db2667, 0xafdd982fe468cdc, 0x3b601b339aabd95d, 0x2e97dafa48478421, 0x3670798a8292b7b}, {0x10446e9825a114f6, 0x49b7a272765b0d6c, 0xb907df9f47291c39, 0xfe1771a2eb97ba6d, 0xad85f215ced88038, 0x1baafd30e707156}};
const const fp2_t xQA = {{0xd64d88142398fc70, 0x8cd791e2b175b8ad, 0x8cf816a594e65996, 0xdc15534f4bbc3e, 0x2ebd5f0fca9cb695, 0x2677728640635e3}, {0x8e859814dd48f154, 0x400b48d3d3fb2e17, 0x9e315059bbc401a9, 0x26c24fc85c0a4034, 0x2095f2ade3a1cc0e, 0x789dae43794796}};
const const fp2_t xQB = {{0x29ebd3656c338c34, 0x2bfcf65c705b22cb, 0xc34d5916fff804ae, 0x936fa5577596f777, 0x88bc262ea82314b1, 0x3cb841bc5ebf63f}, {0x1cd8d5a530a1914c, 0xaa47dc464b7fe567, 0xb2f6cfba20a12302, 0xbdec2a7f8ed5764a, 0x8d8caffb90342f7, 0x2bc600de26023a0}};
const const fp2_t xQ2 = {{0x17df8f9d274de7f, 0x351632cce83ec8aa, 0x56e019deae8daf7e, 0x3da35b5dc1820a3b, 0xbb60de7d759b75b1, 0x2e81949d5d0a4d9}, {0xa4efe85f225c5804, 0x9cbd9fc32e16b4f8, 0xa8be541ed7c20bbc, 0xe057875bd571d902, 0x35f5baf03dab21ff, 0x3493d2784699545}};
const const fp2_t xQ3 = {{0x607226ec950fa8e9, 0x1e2e9c0c29c80afd, 0xa031936b9cf6a2c0, 0x7315c851c532a4a7, 0x2d60288e81b052f1, 0xe41ee69523a243}, {0x574790267f7ab302, 0xce892b253c3a394c, 0xb5b3137fc2ec0d34, 0x7f542df49cea32a5, 0x33f72d3e5b05e6c6, 0x39c6516fbb1f6c6}};
const const fp2_t xPQA = {{0x55c5c814e95ff9e, 0x624aa7502d08f66d, 0xfaef96a43369b1b5, 0x6bd0164a386601da, 0xc4624eccbcab4884, 0x10154ec03218312}, {0x4fbfbe9e5f4e4beb, 0x1392132cc9a7a298, 0x87bee2902df2694c, 0x2fd70dedc82c836c, 0xb969a66833ea4330, 0xac80d610eac86e}};
const const fp2_t xPQB = {{0xef90e01f16ec0b, 0xbe3b230014cdc8ca, 0x11d8068a91007c6a, 0xef60fc7a468eb46, 0x6ebe6eb84394eacc, 0xb27d0c0b9cc97e}, {0xfb44d144ffbc728, 0x35fed8aabb632fb0, 0xbce80df03ad44c4c, 0x94e973d6d612e79a, 0xf90b559988365d91, 0x1d8b3925fcef701}};
const const fp2_t xPQ2 = {{0xb37f8fba3f4420f8, 0x8d48f1acb03706df, 0x5f5d4860530ffdbc, 0x3346cb7307f4e98e, 0xebbd3a151d8187ef, 0x14e3e664b5f52b0}, {0xdab91da8f4656795, 0xdbdcf3c3108cac88, 0x272d467ca27bde21, 0x147ed2cd9dc73cf0, 0x67421707fd5d4d50, 0x1c9f704aa559bda}};
const const fp2_t xPQ3 = {{0xcc5225236d2d7e2c, 0x5c1cc0455811dfd3, 0xd863b10782668e01, 0x5e6d032ac45b3bf9, 0xcab4dd5d95d6202b, 0x36835aa9dc568a3}, {0x372f514559d1038, 0x2064004ad7d5597e, 0xdcfd00d0e96c462c, 0x13a95de9ef3231b6, 0x9302577b0a9a21f7, 0x715073629aff4}};
#endif
#endif
