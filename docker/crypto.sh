#!/bin/bash
sed -i 's/^\tadr\s\+sm3const_adr,SM3_CONSTS$/\tadrp    sm3const_adr, SM3_CONSTS\
\tadd     sm3const_adr, sm3const_adr, :lo12:SM3_CONSTS/' /root/spdk/isa-l-crypto/sm3_mb/aarch64/sm3_mb_sve.S

sed -i 's/^\tadr\s\+key_adr, KEY$/\tadrp    key_adr, KEY\
\tadd     key_adr, key_adr, :lo12:KEY/' /root/spdk/isa-l-crypto/sha512_mb/aarch64/sha512_mb_x1_ce.S

sed -i 's/^\tadr\s\+key_adr, KEY$/\tadrp    key_adr, KEY\
\tadd     key_adr, key_adr, :lo12:KEY/' /root/spdk/isa-l-crypto/sha512_mb/aarch64/sha512_mb_x2_ce.S

sed -i 's/^\tadr\s\+tmp, KEY$/\tadrp    tmp, KEY\
\tadd     tmp, tmp, :lo12:KEY/' /root/spdk/isa-l-crypto/sha256_mb/aarch64/sha256_mb_x1_ce.S

sed -i 's/^\tadr\s\+tmp, KEY$/\tadrp    tmp, KEY\
\tadd     tmp, tmp, :lo12:KEY/' /root/spdk/isa-l-crypto/sha256_mb/aarch64/sha256_mb_x2_ce.S

sed -i 's/^\tadr\s\+tmp, KEY$/\tadrp    tmp, KEY\
\tadd     tmp, tmp, :lo12:KEY/' /root/spdk/isa-l-crypto/sha256_mb/aarch64/sha256_mb_x3_ce.S

sed -i 's/^\tadr\s\+tmp, KEY$/\tadrp    tmp, KEY\
\tadd     tmp, tmp, :lo12:KEY/' /root/spdk/isa-l-crypto/sha256_mb/aarch64/sha256_mb_x4_ce.S

sed -i 's/^\tadr\s\+mur_c1, C1$/\tadrp    mur_c1, C1\
\tadd     mur_c1, mur_c1, :lo12:C1/' /root/spdk/isa-l-crypto/mh_sha1_murmur3_x64_128/aarch64/mh_sha1_murmur3_block_asimd.S

sed -i 's/^\tadr\s\+mur_c2, C2$/\tadrp    mur_c2, C2\
\tadd     mur_c2, mur_c2, :lo12:C2/' /root/spdk/isa-l-crypto/mh_sha1_murmur3_x64_128/aarch64/mh_sha1_murmur3_block_asimd.S

sed -i 's/^\tadr\s\+tmp, N1$/\tadrp    tmp, N1\
\tadd     tmp, tmp, :lo12:N1/' /root/spdk/isa-l-crypto/mh_sha1_murmur3_x64_128/aarch64/mh_sha1_murmur3_block_asimd.S

sed -i 's/^\tadr\s\+tmp, N2$/\tadrp    tmp, N2\
\tadd     tmp, tmp, :lo12:N2/' /root/spdk/isa-l-crypto/mh_sha1_murmur3_x64_128/aarch64/mh_sha1_murmur3_block_asimd.S

sed -i 's/^\tadr\s\+sha1key_adr, KEY_0$/\tadrp    sha1key_adr, KEY_0\
\tadd     sha1key_adr, sha1key_adr, :lo12:KEY_0/' /root/spdk/isa-l-crypto/mh_sha1_murmur3_x64_128/aarch64/sha1_asimd_common.S

sed -i 's/^\tadr\s\+sha1key_adr, KEY_1$/\tadrp    sha1key_adr, KEY_1\
\tadd     sha1key_adr, sha1key_adr, :lo12:KEY_1/' /root/spdk/isa-l-crypto/mh_sha1_murmur3_x64_128/aarch64/sha1_asimd_common.S

sed -i 's/^\tadr\s\+sha1key_adr, KEY_2$/\tadrp    sha1key_adr, KEY_2\
\tadd     sha1key_adr, sha1key_adr, :lo12:KEY_2/' /root/spdk/isa-l-crypto/mh_sha1_murmur3_x64_128/aarch64/sha1_asimd_common.S

sed -i 's/^\tadr\s\+sha1key_adr, KEY_3$/\tadrp    sha1key_adr, KEY_3\
\tadd     sha1key_adr, sha1key_adr, :lo12:KEY_3/' /root/spdk/isa-l-crypto/mh_sha1_murmur3_x64_128/aarch64/sha1_asimd_common.S

sed -i 's/^\tadr\s\+md5key_adr,MD5_CONST_KEYS$/\tadrp    md5key_adr,MD5_CONST_KEYS\
\tadd     md5key_adr, md5key_adr, :lo12:MD5_CONST_KEYS/' /root/spdk/isa-l-crypto/md5_mb/aarch64/md5_mb_sve.S
