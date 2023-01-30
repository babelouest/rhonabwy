/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>

#include <check.h>
#include <yder.h>
#include <orcania.h>
#include <rhonabwy.h>

#define TOKEN_SE "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.BMkD42WQBkpbOFtk6cAlK0vPS_zN3NJ1VVQFbgdnbVwbu21bJSQuHGypqvWXY336MC4uWoZ01E1Di4WD935Xv47UxIFmg_VLmCtvLPa9Bt7YncUHlM6IZ5EMUYJmasd3JKg5cs213djBUt4hsG0FBqYWZJGZovBBzHkjdI8qV7Vw29_xfBS_3LGiBYPnAMU8TFgKs49tAyWiDI6wb1rN59Hw5O-sQ1wVggVYuMwTmaYekiXCkDS8WMouYHQwq_183skoRuhG6NDHdw_NCMRFI6yfdaXDB3L_8O2ileWwGwlN1sDNPnFfUJGwb55D0Jc57vb4eWH0OSVo4Pk6wQlz-A.KDT-hqGQiYZgM5O2aMjbZg.88OzLv6i_VweilpNc_YNYR4p8m32dIUW_Hy3aYjyJA7Dfavwy5BsuNganQiN5Sq6CmNElRyoX2MLxbxrgkqKt1I6sYYavTPTcKTsdQW7vudwggmRJqGZn6kPl1OASlJ9Xnf0o5dRuBCKh0grHYl-b4L3pP56tvlx9tb9Cjb-wKpOjhl0sb8ItVLrc9Ez6BLOqGd4RH_tyBOK7na5Yrhcy4lvP8I1lmsjiQ8bTYzulnQhgtJHpgOim0p5NoSSjQDrBZYp-C0MIMsU2IQaFe7OC34g1j9j7IAvfBk8cXmBALZrci_3NBy2hTM55VYM0OcD6Fk4c6929NgwCGRh5WDthZtQtejkozI_iU3U-ufcGOA_JGj0QPuldK8SFJP9nRzCIRwbkCQmYvVEGzBjUB_AoNsTdwMdwH4-dslPWCypDVfDq8qIXIe2mswn0zQrhM39whWRuS0Wp-bN6R26fkQ9jQpbaTue_viV7gg4a3gPzW93-mqqwnM--2pbcKRFcSEYfYwxHCWoN_YFnsJow-t7V8hp68rlNurEIY3LxAYKYZUnqxaYlUe4mLxt6UO0thomw8deQyR5Jle-lS5vdE1oRA.HdJ_bLTq0p_hrUZjCUsomw"
#define TOKEN_SE_INVALID_HEADER_B64 "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU.BMkD42WQBkpbOFtk6cAlK0vPS_zN3NJ1VVQFbgdnbVwbu21bJSQuHGypqvWXY336MC4uWoZ01E1Di4WD935Xv47UxIFmg_VLmCtvLPa9Bt7YncUHlM6IZ5EMUYJmasd3JKg5cs213djBUt4hsG0FBqYWZJGZovBBzHkjdI8qV7Vw29_xfBS_3LGiBYPnAMU8TFgKs49tAyWiDI6wb1rN59Hw5O-sQ1wVggVYuMwTmaYekiXCkDS8WMouYHQwq_183skoRuhG6NDHdw_NCMRFI6yfdaXDB3L_8O2ileWwGwlN1sDNPnFfUJGwb55D0Jc57vb4eWH0OSVo4Pk6wQlz-A.KDT-hqGQiYZgM5O2aMjbZg.88OzLv6i_VweilpNc_YNYR4p8m32dIUW_Hy3aYjyJA7Dfavwy5BsuNganQiN5Sq6CmNElRyoX2MLxbxrgkqKt1I6sYYavTPTcKTsdQW7vudwggmRJqGZn6kPl1OASlJ9Xnf0o5dRuBCKh0grHYl-b4L3pP56tvlx9tb9Cjb-wKpOjhl0sb8ItVLrc9Ez6BLOqGd4RH_tyBOK7na5Yrhcy4lvP8I1lmsjiQ8bTYzulnQhgtJHpgOim0p5NoSSjQDrBZYp-C0MIMsU2IQaFe7OC34g1j9j7IAvfBk8cXmBALZrci_3NBy2hTM55VYM0OcD6Fk4c6929NgwCGRh5WDthZtQtejkozI_iU3U-ufcGOA_JGj0QPuldK8SFJP9nRzCIRwbkCQmYvVEGzBjUB_AoNsTdwMdwH4-dslPWCypDVfDq8qIXIe2mswn0zQrhM39whWRuS0Wp-bN6R26fkQ9jQpbaTue_viV7gg4a3gPzW93-mqqwnM--2pbcKRFcSEYfYwxHCWoN_YFnsJow-t7V8hp68rlNurEIY3LxAYKYZUnqxaYlUe4mLxt6UO0thomw8deQyR5Jle-lS5vdE1oRA.HdJ_bLTq0p_hrUZjCUsomw"
#define TOKEN_SE_INVALID_CLAIMS_B64 ";error;.BMkD42WQBkpbOFtk6cAlK0vPS_zN3NJ1VVQFbgdnbVwbu21bJSQuHGypqvWXY336MC4uWoZ01E1Di4WD935Xv47UxIFmg_VLmCtvLPa9Bt7YncUHlM6IZ5EMUYJmasd3JKg5cs213djBUt4hsG0FBqYWZJGZovBBzHkjdI8qV7Vw29_xfBS_3LGiBYPnAMU8TFgKs49tAyWiDI6wb1rN59Hw5O-sQ1wVggVYuMwTmaYekiXCkDS8WMouYHQwq_183skoRuhG6NDHdw_NCMRFI6yfdaXDB3L_8O2ileWwGwlN1sDNPnFfUJGwb55D0Jc57vb4eWH0OSVo4Pk6wQlz-A.KDT-hqGQiYZgM5O2aMjbZg.88OzLv6i_VweilpNc_YNYR4p8m32dIUW_Hy3aYjyJA7Dfavwy5BsuNganQiN5Sq6CmNElRyoX2MLxbxrgkqKt1I6sYYavTPTcKTsdQW7vudwggmRJqGZn6kPl1OASlJ9Xnf0o5dRuBCKh0grHYl-b4L3pP56tvlx9tb9Cjb-wKpOjhl0sb8ItVLrc9Ez6BLOqGd4RH_tyBOK7na5Yrhcy4lvP8I1lmsjiQ8bTYzulnQhgtJHpgOim0p5NoSSjQDrBZYp-C0MIMsU2IQaFe7OC34g1j9j7IAvfBk8cXmBALZrci_3NBy2hTM55VYM0OcD6Fk4c6929NgwCGRh5WDthZtQtejkozI_iU3U-ufcGOA_JGj0QPuldK8SFJP9nRzCIRwbkCQmYvVEGzBjUB_AoNsTdwMdwH4-dslPWCypDVfDq8qIXIe2mswn0zQrhM39whWRuS0Wp-bN6R26fkQ9jQpbaTue_viV7gg4a3gPzW93-mqqwnM--2pbcKRFcSEYfYwxHCWoN_YFnsJow-t7V8hp68rlNurEIY3LxAYKYZUnqxaYlUe4mLxt6UO0thomw8deQyR5Jle-lS5vdE1oRA.HdJ_bLTq0p_hrUZjCUsomw"
#define TOKEN_SE_INVALID_DOTS "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0BMkD42WQBkpbOFtk6cAlK0vPS_zN3NJ1VVQFbgdnbVwbu21bJSQuHGypqvWXY336MC4uWoZ01E1Di4WD935Xv47UxIFmg_VLmCtvLPa9Bt7YncUHlM6IZ5EMUYJmasd3JKg5cs213djBUt4hsG0FBqYWZJGZovBBzHkjdI8qV7Vw29_xfBS_3LGiBYPnAMU8TFgKs49tAyWiDI6wb1rN59Hw5O-sQ1wVggVYuMwTmaYekiXCkDS8WMouYHQwq_183skoRuhG6NDHdw_NCMRFI6yfdaXDB3L_8O2ileWwGwlN1sDNPnFfUJGwb55D0Jc57vb4eWH0OSVo4Pk6wQlz-A.KDT-hqGQiYZgM5O2aMjbZg.88OzLv6i_VweilpNc_YNYR4p8m32dIUW_Hy3aYjyJA7Dfavwy5BsuNganQiN5Sq6CmNElRyoX2MLxbxrgkqKt1I6sYYavTPTcKTsdQW7vudwggmRJqGZn6kPl1OASlJ9Xnf0o5dRuBCKh0grHYl-b4L3pP56tvlx9tb9Cjb-wKpOjhl0sb8ItVLrc9Ez6BLOqGd4RH_tyBOK7na5Yrhcy4lvP8I1lmsjiQ8bTYzulnQhgtJHpgOim0p5NoSSjQDrBZYp-C0MIMsU2IQaFe7OC34g1j9j7IAvfBk8cXmBALZrci_3NBy2hTM55VYM0OcD6Fk4c6929NgwCGRh5WDthZtQtejkozI_iU3U-ufcGOA_JGj0QPuldK8SFJP9nRzCIRwbkCQmYvVEGzBjUB_AoNsTdwMdwH4-dslPWCypDVfDq8qIXIe2mswn0zQrhM39whWRuS0Wp-bN6R26fkQ9jQpbaTue_viV7gg4a3gPzW93-mqqwnM--2pbcKRFcSEYfYwxHCWoN_YFnsJow-t7V8hp68rlNurEIY3LxAYKYZUnqxaYlUe4mLxt6UO0thomw8deQyR5Jle-lS5vdE1oRA.HdJ_bLTq0p_hrUZjCUsomw"
#define TOKEN_SE_INVALID_ENCRYPTION "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.BMkD42WQBkpbOFtk6cAlK0vPS_zN3NJ1VVQFbgdnbVwbu21bJSQuHGypqvWXY336MC4uWoZ01E1Di4WD935Xv47UxIFmg_VLmCtvLPa9Bt7YncUHlM6IZ5EMUYJmasd3JKg5cs213djBUt4hsG0FBqYWZJGZovBBzHkjdI8qV7Vw29_xfBS_3LGiBYPnAMU8TFgKs49tAyWiDI6wb1rN59Hw5O-sQ1wVggVYuMwTmaYekiXCkDS8WMouYHQwq_183skoRuhG6NDHdw_NCMRFI6yfdaXDB3L_8O2ileWwGwlN1sDNPnFfUJGwb55D0Jc57vb4eWH0OSVo4Pk6wQlz-A.KDT-hqGQiYZgM5O2aMjbZg.88OzLv6i_VweilpNc_YNYR4p8m32dIUW_Hy3aYjyJA7Dfavwy5BsuNganQiN5Sq6CmNElRyoX2MLxbxrgkqKt1I6sYYavTPTcKTsdQW7vudwggmRJqGZn6kPl1OASlJ9Xnf0o5dRuBCKh0grHYl-b4L3pP56tvlx9tb9Cjb-wKpOjhl0sb8ItVLrc9Ez6BLOqGd4RH_tyBOK7na5Yrhcy4lvP8I1lmsjiQ8bTYzulnQhgtJHpgOim0p5NoSSjQDrBZYp-C0MIMsU2IQaFe7OC34g1j9j7IAvfBk8cXmBALZrci_3NBy2hTM55VYM0OcD6Fk4c6929NgwCGRh5WDthZtQtejkozI_iU3U-ufcGOA_JGj0QPuldK8SFJP9nRzCIRwbkCQmYvVEGzBjUB_AoNsTdwMdwH4-dslPWCypDVfDq8qIXIe2mswn0zQrhM39whWRuS0Wp-bN6R26fkQ9jQpbaTue_viV7gg4a3gPzW93-mqqwnM--2pbcKRFcSEYfYwxHCWoN_YFnsJow-t7V8hp68rlNurEIY3LxAYKYZUnqxaYlUe4mLxt5UO0thomw8deQyR5Jle-lS5vdE1oRA.HdJ_bLTq0p_hrUZjCUsomw"
#define TOKEN_ES "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjMifQ.ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1UwRXhYelVpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC5NQjFub3prM2xQOHRVVDVkZm5HdzBud1ktaXVBZ1FTMy1RYnpoWEs5WVBfVWtBYkVVTkhzVXBKME5GM2kwSkxtWHhnQ2VrWFlocWprSTBIUVNINmtmRjhqOXgteTJfX01nLU9tVnZVYjM4aTRneEZBVmhKTHd5TkNhV3NMLTk1VV95QW5DZDJ1eVpQOFdWOVRRY0xKOGxSaFZOTC1JcXFkMDctb2VDRVBfYmVxZzZwOWtod1c3Z291T0wzSG1IMkpBR3dOdXJHV3I2S3luQ2hXN1NBUHlvTVZWVEl1Mmwxc2pmM0E4b1pvZl9aZmd6ZmVGVFJseGVjb1dIVTQ3UmJRcTRUQ3pQdFlRZUxRVF9fTkk3VjI4T2RvaEw2am5lWkdKaTg2Umk2NnIwRXNoS0tJcWI4UTJwRzRUTS1QTm1BVWJsdzB4R2FRdGdGaDhFdGRKaGFMbmcudVA2ME0ya0ltQUZUTUdqYWhhMjlnQS5MZUNXQk9KMDhaVjVpaFJWRE93emgzYVRrTXFGYkIxMzBubXpfRUx3b1pQWEhLaWlmNHZRRGNIOGFkWWZCQ2dLLldLSEI4aGItNl81aDBmX1dEc05DZGc.gcUVTzWlR-R3T3w6cUyf8_C1gUTg6TWLO-QHpsjirUJR3pRwz3w48SkPMladWFM6EU88cjCW_bo2xO-LTpgIhd78mjL0yUadVWodOjqEj19plr4A1pXV3TBmHoFr6FiqcifgL55K-PNRQsa001SlCYx8rLj033hEzbSTJiPEC2CJnwGZAfKGMK87LHXc_nxOvmaEIkbBY60nPcH1HNgbu6CSrk4M5GR6UWF_23QX8RbEQfKkADqjoiKOHdDE5-4mNej_vg-ycORXNuOCHw9iDHVZp_yEKgabayW-Xn0oPH0yamCC--RQyPohkT3R22T2Ma7BdgvVIu385Yh_JqTKFw"
#define TOKEN_ES_INVALID_HEADER_B64 ";error;.ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1UwRXhYelVpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC5NQjFub3prM2xQOHRVVDVkZm5HdzBud1ktaXVBZ1FTMy1RYnpoWEs5WVBfVWtBYkVVTkhzVXBKME5GM2kwSkxtWHhnQ2VrWFlocWprSTBIUVNINmtmRjhqOXgteTJfX01nLU9tVnZVYjM4aTRneEZBVmhKTHd5TkNhV3NMLTk1VV95QW5DZDJ1eVpQOFdWOVRRY0xKOGxSaFZOTC1JcXFkMDctb2VDRVBfYmVxZzZwOWtod1c3Z291T0wzSG1IMkpBR3dOdXJHV3I2S3luQ2hXN1NBUHlvTVZWVEl1Mmwxc2pmM0E4b1pvZl9aZmd6ZmVGVFJseGVjb1dIVTQ3UmJRcTRUQ3pQdFlRZUxRVF9fTkk3VjI4T2RvaEw2am5lWkdKaTg2Umk2NnIwRXNoS0tJcWI4UTJwRzRUTS1QTm1BVWJsdzB4R2FRdGdGaDhFdGRKaGFMbmcudVA2ME0ya0ltQUZUTUdqYWhhMjlnQS5MZUNXQk9KMDhaVjVpaFJWRE93emgzYVRrTXFGYkIxMzBubXpfRUx3b1pQWEhLaWlmNHZRRGNIOGFkWWZCQ2dLLldLSEI4aGItNl81aDBmX1dEc05DZGc.gcUVTzWlR-R3T3w6cUyf8_C1gUTg6TWLO-QHpsjirUJR3pRwz3w48SkPMladWFM6EU88cjCW_bo2xO-LTpgIhd78mjL0yUadVWodOjqEj19plr4A1pXV3TBmHoFr6FiqcifgL55K-PNRQsa001SlCYx8rLj033hEzbSTJiPEC2CJnwGZAfKGMK87LHXc_nxOvmaEIkbBY60nPcH1HNgbu6CSrk4M5GR6UWF_23QX8RbEQfKkADqjoiKOHdDE5-4mNej_vg-ycORXNuOCHw9iDHVZp_yEKgabayW-Xn0oPH0yamCC--RQyPohkT3R22T2Ma7BdgvVIu385Yh_JqTKFw"
#define TOKEN_ES_INVALID_CLAIMS_B64 "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjMifQ.;error;.gcUVTzWlR-R3T3w6cUyf8_C1gUTg6TWLO-QHpsjirUJR3pRwz3w48SkPMladWFM6EU88cjCW_bo2xO-LTpgIhd78mjL0yUadVWodOjqEj19plr4A1pXV3TBmHoFr6FiqcifgL55K-PNRQsa001SlCYx8rLj033hEzbSTJiPEC2CJnwGZAfKGMK87LHXc_nxOvmaEIkbBY60nPcH1HNgbu6CSrk4M5GR6UWF_23QX8RbEQfKkADqjoiKOHdDE5-4mNej_vg-ycORXNuOCHw9iDHVZp_yEKgabayW-Xn0oPH0yamCC--RQyPohkT3R22T2Ma7BdgvVIu385Yh_JqTKFw"
#define TOKEN_ES_INVALID_DOTS "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjMifQZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1UwRXhYelVpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC5NQjFub3prM2xQOHRVVDVkZm5HdzBud1ktaXVBZ1FTMy1RYnpoWEs5WVBfVWtBYkVVTkhzVXBKME5GM2kwSkxtWHhnQ2VrWFlocWprSTBIUVNINmtmRjhqOXgteTJfX01nLU9tVnZVYjM4aTRneEZBVmhKTHd5TkNhV3NMLTk1VV95QW5DZDJ1eVpQOFdWOVRRY0xKOGxSaFZOTC1JcXFkMDctb2VDRVBfYmVxZzZwOWtod1c3Z291T0wzSG1IMkpBR3dOdXJHV3I2S3luQ2hXN1NBUHlvTVZWVEl1Mmwxc2pmM0E4b1pvZl9aZmd6ZmVGVFJseGVjb1dIVTQ3UmJRcTRUQ3pQdFlRZUxRVF9fTkk3VjI4T2RvaEw2am5lWkdKaTg2Umk2NnIwRXNoS0tJcWI4UTJwRzRUTS1QTm1BVWJsdzB4R2FRdGdGaDhFdGRKaGFMbmcudVA2ME0ya0ltQUZUTUdqYWhhMjlnQS5MZUNXQk9KMDhaVjVpaFJWRE93emgzYVRrTXFGYkIxMzBubXpfRUx3b1pQWEhLaWlmNHZRRGNIOGFkWWZCQ2dLLldLSEI4aGItNl81aDBmX1dEc05DZGc.gcUVTzWlR-R3T3w6cUyf8_C1gUTg6TWLO-QHpsjirUJR3pRwz3w48SkPMladWFM6EU88cjCW_bo2xO-LTpgIhd78mjL0yUadVWodOjqEj19plr4A1pXV3TBmHoFr6FiqcifgL55K-PNRQsa001SlCYx8rLj033hEzbSTJiPEC2CJnwGZAfKGMK87LHXc_nxOvmaEIkbBY60nPcH1HNgbu6CSrk4M5GR6UWF_23QX8RbEQfKkADqjoiKOHdDE5-4mNej_vg-ycORXNuOCHw9iDHVZp_yEKgabayW-Xn0oPH0yamCC--RQyPohkT3R22T2Ma7BdgvVIu385Yh_JqTKFw"
#define TOKEN_ES_INVALID_SIGNATURE "eyJ0eXAiOiJKV1QiLCJjdHkiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjMifQ.ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1UwRXhYelVpTENKbGJtTWlPaUpCTVRJNFEwSkRMVWhUTWpVMkluMC5NQjFub3prM2xQOHRVVDVkZm5HdzBud1ktaXVBZ1FTMy1RYnpoWEs5WVBfVWtBYkVVTkhzVXBKME5GM2kwSkxtWHhnQ2VrWFlocWprSTBIUVNINmtmRjhqOXgteTJfX01nLU9tVnZVYjM4aTRneEZBVmhKTHd5TkNhV3NMLTk1VV95QW5DZDJ1eVpQOFdWOVRRY0xKOGxSaFZOTC1JcXFkMDctb2VDRVBfYmVxZzZwOWtod1c3Z291T0wzSG1IMkpBR3dOdXJHV3I2S3luQ2hXN1NBUHlvTVZWVEl1Mmwxc2pmM0E4b1pvZl9aZmd6ZmVGVFJseGVjb1dIVTQ3UmJRcTRUQ3pQdFlRZUxRVF9fTkk3VjI4T2RvaEw2am5lWkdKaTg2Umk2NnIwRXNoS0tJcWI4UTJwRzRUTS1QTm1BVWJsdzB4R2FRdGdGaDhFdGRKaGFMbmcudVA2ME0ya0ltQUZUTUdqYWhhMjlnQS5MZUNXQk9KMDhaVjVpaFJWRE93emgzYVRrTXFGYkIxMzBubXpfRUx3b1pQWEhLaWlmNHZRRGNIOGFkWWZCQ2dLLldLSEI4aGItNl81aDBmX1dEc05DZGc.gcUVTzWlR-R3T3w6cUyf8_C1gUTg6TWLO-QHpsjirUJR3pRwz3w48SkPMladWFM6EU88cjCW_bo2xO-LTpgIhd78mjL0yUadVWodOjqEj19plr4A1pXV3TBmHoFr6FiqcifgL55K-PNRQsa001SlCYx8rLj033hEzbSTJiPEC2CJnwGZAfKGMK87LHXc_nxO6maEIkbBY60nPcH1HNgbu6CSrk4M5GR6UWF_23QX8RbEQfKkADqjoiKOHdDE5-4mNej_vg-ycORXNuOCHw9iDHVZp_yEKgabayW-Xn0oPH0yamCC--RQyPohkT3R22T2Ma7BdgvVIu385Yh_JqTKFw"

const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                   "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                   "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                   ",\"e\":\"AQAB\",\"alg\":\"RSA1_5\",\"kid\":\"2011-04-29\"}";
const char jwk_privkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                    "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                    "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                    "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                    "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                    "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                    "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                    "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                    "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                    "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                    "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                    "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                    "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                    "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RSA1_5\",\"kid\":\"2011-04-29\"}";
const char jwk_pubkey_rsa_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ANjyvB_f8xm80wMZM4Z7VO6UrTaFoDd68pgf2BCnnMsnH9lo4z40Yg-wWFhPhgZmSTFZjYUkWHGZoEpordO8xq6d_o3gkL2-ValGfxD8"
                                    "2B7465IKNodJY7bldLaBqsVcQrottkL2UC3SXuIkDfZGG6_XU6Lr14rgNvw65mWavejYLNz2GVvmc54p36PArwPSY8fvdQsijrmrvsxx9av0qZASbxjfHkuibnsC4sW3b"
                                    "bsObZG_eOBkEwOwh_RVSV5GyprA4mZfnj_rTnWVN4OENa756cyk1JwWRzRWR0Q7xdlvcAzga3S3M_9dJb386Oip3SsFhIeZekyh2lAEi2E5VUWP8uOf-UCuEj04B9hNl5"
                                    "szmNMts5AsBxBKwK_ixWNif8NBGQyA8mqRpYr7ddaBnCxreDuZyV6AwPBRfIOb29zgIi5OZzISsvFjFACDrgtX5sF_M_Q6usnyN-3LKoqHMqcL3dk0_a93gsuYMpK4OPm"
                                    "N6-82CekUsJ_m--3cZbknmeixPnRQGJLZNSZrpd0KZ1A0Dzmkr6RqWTlu51-cI50lyZXJiHR8hv-_tW2iRN3DWs6uI24S44-1-mSYfXL5vLYu6cBlIGYh55wLHK4GwyfF"
                                    "-GopckkedidJjX-zVPwJSq2CjmgitDvjoZMaDawoKgkH_uTWqobUNIS_4BPQiAET\",\"e\":\"AQAB\",\"kid\":\"2\"}";
const char jwk_privkey_rsa_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ANjyvB_f8xm80wMZM4Z7VO6UrTaFoDd68pgf2BCnnMsnH9lo4z40Yg-wWFhPhgZmSTFZjYUkWHGZoEpordO8xq6d_o3gkL2-ValGfxD"
                                     "82B7465IKNodJY7bldLaBqsVcQrottkL2UC3SXuIkDfZGG6_XU6Lr14rgNvw65mWavejYLNz2GVvmc54p36PArwPSY8fvdQsijrmrvsxx9av0qZASbxjfHkuibnsC4sW"
                                     "3bbsObZG_eOBkEwOwh_RVSV5GyprA4mZfnj_rTnWVN4OENa756cyk1JwWRzRWR0Q7xdlvcAzga3S3M_9dJb386Oip3SsFhIeZekyh2lAEi2E5VUWP8uOf-UCuEj04B9h"
                                     "Nl5szmNMts5AsBxBKwK_ixWNif8NBGQyA8mqRpYr7ddaBnCxreDuZyV6AwPBRfIOb29zgIi5OZzISsvFjFACDrgtX5sF_M_Q6usnyN-3LKoqHMqcL3dk0_a93gsuYMpK"
                                     "4OPmN6-82CekUsJ_m--3cZbknmeixPnRQGJLZNSZrpd0KZ1A0Dzmkr6RqWTlu51-cI50lyZXJiHR8hv-_tW2iRN3DWs6uI24S44-1-mSYfXL5vLYu6cBlIGYh55wLHK4"
                                     "GwyfF-GopckkedidJjX-zVPwJSq2CjmgitDvjoZMaDawoKgkH_uTWqobUNIS_4BPQiAET\",\"e\":\"AQAB\",\"d\":\"cf9SlRkzf5G1-4nRhlfmMBuVzPF4V87WD"
                                     "NOm0FGS1TkwxigUSIp0ALR0J6tZzKEQ0sqwz4ZipwbHsHHC7WDjsbu5l8mppNqP3ov5lu6VjejUt_9_2aTZrbBynLgUCPLK6VO90v_k7778Nq4lXARI5iQqgZCVyRa6L"
                                     "d2xVTBznBeDs3PprV2x4Sk1p7FHBaYW4mdURE6bWrsBXiJ_qiS8uMTG9fW_0JSAo0jH6obRNRqGvrAzDw3m4-ht-Bicndpq-dhi3tJdsE6wAp8u9X-SSehuTydJxN77-"
                                     "WdguV0DQJcK9Okz7bearhO_Ek8D_8XKPqH-mtYt6nid47APoT3kLNp1v5qiXQ8hLN4N1YM_s7LG44Gtns32Vzs7nwwBnBHAdhUxm5q40twVGXraw6SrTZC1hMpVCgJvp"
                                     "Ta-Ebz8RM7b7Qw142_4BRfi4p2QuOxoxY5ahmKD7xF8MH5307hPCC2-MO8FNe8c5sr4soEj93eFEf9V0UV5YHekopAKHDaS15sSbCIrDk78vFVmO2R6RCa3JKWLhg5Lk"
                                     "V5SeT5u3_TYdQ_3tgpZusuV534DbUV-Ztan2Emu4ds4-icL-SqkXzA_1TvDYtwnMxIWlG07gqTw-BshL2JuY18_8FjVzy4MWB7J8s2GVzJqKT8iY-L4JTJY5cvYsaQkF"
                                     "xRFEc2oE4E\",\"p\":\"AOLIjerOJBuW-Odoq2WSGSRzD5M5i4wwHV88wsNhzLsarB_ebyKwQwEKyalhOAUFTXjUQzg2G8FB9FLPmdgnUukWNCmd4c0pRBKCLNXHQwK"
                                     "uYTHf8lkfn2WchyGGIVQUFbgSdJtN6PGZbRa-26sz4xQgtyiFLerA8shwGl6Q07Sjd6CvRi-NvGqEW2LCz10iNPCqzQYfS0cPWhYXDrIqL_BFTo6A3bU0ifg_NukCvcR"
                                     "KZtlD2FaMCMF5xxfoCMtfXF1Owf_QwCAI5GebTbmLf3BmaCNjlmFm6nR1Vo-17Tk0nq3_rPYGiqLr2ANk8NHeMs6xe1GcWuO_nD1gE6o5QtM\",\"q\":\"APTlzxeo8"
                                     "IINCZulhQyOr3-zBTAtyaHgHQk2-AQYK98Ev6pfBvxwwMzAkSoVpCm1pxyp3JCSyjRSYFd4ibnZDjwd5p8RBfLr_zEnfx-IdUIrY7SyCGaFcKt2jS__4DUZQZu0-3Ysi"
                                     "dK8AECtVr0pa4XifZQnkqWnOeqkZqW1lT1yI8w4NbpCJVAT3ohhhRbTcCLFMhZjmWt5ZGgPz9r251PE-7i-04UvShSevhwdS6YJ3ma4gWhYbDMoADOXFfc5Qr1LxHd1w"
                                     "8LUk20bYTW_yZM8tDZxOQqkGivFW53kcgifzmKYjADNgQQojKO4KhG7xGxqvNrzNJQjM3SPdmUM4ME\",\"qi\":\"DwIv9lrwRP5ptwss0aNKgE1wRaaT8upXvzzlZA"
                                     "uNwolrVhmft_ELSNFuMRv-FCL1BK7YQgBwqux0_iRljvMcRogpeCs7w9DwLpivWyVcJf4PKZZWWlm7_kjIoVxRmNBzZUPpadCTQpAc8uGDtlz6OVgnvnb8FWtYDmHJMy"
                                     "UUdOb5Yxyg98P69pQ9ubPkkRwisDNnujjU3FCdiKZM1W1-l-qGJSHx0L8FEV3pckdOqzejw4jvb0mQroS5_UyeeY5nD93dwyI2faoD6K8xdh_Q1l6yW-7S3z7Z9qTkcP"
                                     "Ikb_BnWE59bAJniLDFx9KCSLMXv-_AhtY8AoGmSwT2rzAFpw\",\"dp\":\"ALDkPIZNOq7miMl_xElatw_OS_TLawTzNsXlkAl0jIvZFy9YghltoSX78yaSNW79HtvD"
                                     "vZbn5ahNuLSrR9XpfmtfLVrU0p8DtBw3u58YaTV7LUcI5nEMEHniqSjGBdMeQ36rrpbBI5Tn1sZqItAcjeBSUGtjzlgRHo6nmnnuv6Nj6ljEvpszFCeFi_6x86syllau"
                                     "83L2D_Kij-MxIv5nl7LzbH4NGGJSU9f1_u-rerfUTPrlR6biXaYERf5ouAtiG5qQZxQSEPor1XTXF75FiCb1Sf9om5DoBLLIH7fC8QGxAKC6EIBqw9Km4XxsTMd2aOz-"
                                     "VTFoIyEIgWcCPPSG648\",\"dq\":\"GW-xJdz3NhrSj6cOfbJoShQ3Cr0Gv1h-y5E5C3vTOrPMkI6UNC4l6F5r9XoP9gEXHWQLM7z7YZnYxd0QOQxxbQ8SAB2Nh6C5f"
                                     "cqDaqwKude14HPJaZSckkKbAYxLJli8NscCg1C28_tw70bRxo4BzAMtVfESS0BmRJfUzYtht-MeEr0X34O1Sm714yZ141wMvp_KxwaLTd1q72AND8orVskT-Clh4Oh7g"
                                     "k7Gojbsv48w2Wx6jHL6sgmKk9Eyh94br3uqKVpC_f6EXYXFgAaukitw8GKsMQ3AZiF2lZy_t2OZ1SXRDNhLeToY-XxMalEdYsFnYjp2kJhjZMzt2CsRQQ\",\"kid\":\"2\"}";
const char jwk_pubkey_sign_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9EXrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9MCN0WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0_U\",\"e\":\"AQAB\",\"kid\":\"3\"}";
const char jwk_privkey_sign_str[] = "{\"kty\":\"RSA\",\"n\":\"ANgV1GxZbGBMIqqX5QsNrQQnPLk8UpkqH_60EuaHsI8YnUkPmPVXJ_4z_ziqZizvvjp_RhhXX2DnHEQuYwI-SZaBlK1VJiiWH9EXrUeazcpEryFUR0I5iBROcgRJfHSvRvC7D83-xg9xC-NGVvIQ2llduYzmaK8rfuiHWlGqow3O2m5os9NTortdQf7BeTniStDokFvZy-I4i24UFkemoNPWZ9MCN0WTea8n_TQmq9sVHGQtLIFqfblLxbSz_7m4g7_o3WfqlwXkVmCIu1wdzAjZV5BspBGrL0ed5Whpk9-bX69nUDvpcMAaPhuRwZ43e9koVRbVwXCNkne98VAs0_U\",\"e\":\"AQAB\",\"d\":\"AKOVsyDreb5VJRFcuIrrqYWxZqkc37MQTvR1wrE_HAzYp4n-AuAJQT-Sga6WYY-3V53VaG1ZB93GWIHNVCsImJEWPEYUZjTnoeKbOBUzPoPYB3UF5oReJYSp9msEbvGvF9d65fYe4DYkcMl4IK5Uz9hDugrPC4VBOmwyu8-DjLkP8OH-N2-KhJvX_kLKgivfzD3KOp6wryLnKuZYn8N4E6rCiNSfKMgoM60bSHRNi0QHYB2jwqMU5T5EzdpD3Tu_ow6a-sXrW6SG1dtbuStck9hFcQ-QtRCeWoM5pFN8cKOsWBZd1unq-X3gMlCjdXUBUW7BYP44lpYsg1v9l_Ww64E\",\"p\":\"ANmlFUVM-836aC-wK-DekE3s3gl7GZ-9Qca8iKnaIeMszgyaLYkkbYNPpjjsiQHc37IG3axCaywK40PZqODzovL5PnUpwfNrnlMaI042rNaf8q1L4kvaBTkbO9Wbj0sTLMPt1frLQKBRsNDsYamRcL1SwvTC4aI7cgZBrNIBdPiR\",\"q\":\"AP4qYxRNGaI3aeZh5hgKPSGW82X8Ai2MzIKjzSDYmKGcD9HPRV0dAUmDCvqyjwCD6tL9iMtZKPz7VK66-KvV1n91WLMDtRzWs_eFFyDY7BYw47o6IQoZ2RxBT3-7WLhlFflaEner8k23zpGOjZbyzt0SIWRAYR0zlb7LrS_X4fcl\",\"qi\":\"fnlvhYXAn6V0X6gmlwooZUWo9bR7ObChNhrUzMVDOReUVOrzOhlzGhBW1TEFBBr8k44ZWBCTeVEQh--LFHwVvCgEjDBxfjUPUMkeyKZzLhpIUB_cFBAgI7Fyy0yuPpY0mS1PfMt5Y4b6g_JvdBWZZ8VhTcCVG7qDqoH_IJMXPNg\",\"dp\":\"EAsiQUSGf02JJpLG-UGOw5_FUk-XuPW7honZTSP-QX_JBJbM6oIb7IUPjLyq8M82Uio9ZvhSbCG1VQgTcdmj1mNXHk3gtS_msNuJZLeVEBEkU2_3k33TyrzeMUXRT0hvkVXT4zPeZLMA5LW4EUbeV6ZlJqPC_DGDm0B2G9jtpXE\",\"dq\":\"AMTictPUEcpOILO9HG985vPxKeTTfaBpVDbSymDqR_nQmZSOeg3yHQAkCco_rXTZu3rruR7El3K5AlVEMsNxp3IepbIuagrH6qsPpuXkA6YBAzdMNjHL6hnwIbQxnT1h2M7KzklzogRAIT0x706CEmq_06wEDvZ-8j3VKvhHxBwd\",\"kid\":\"3\"}";
const char jwk_pubkey_sign_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ALZfFvsvNegnsnjhAydGJ17C9Ny5-M1UqRbcgaPUFRqvfn2P2Yz5rjGTnfFKe9E6xANSNzKRdb5ltNeeJT0inSi2meACAXE68Ud7d2JvlkxQPvz1tJyCKvQFktGwlqwW5F8r_spfT1qJsf_DpZWjsXFrkY7sdrHJdoeQZDIYx0fsGdzlA0uGoGimPlCCExYLcqsjjh3Dqv8V1xJ4jm5S8198v3FJXXm5BN_GWAmExuDOq6ul8MqcECXBQ4LavxFlB5kGgPsxvFjTK72_2YdNDQPkKmV56vShm50BaEqzXU0A2MYeTyabX7d4goI_B7IeX5tGqMjBrlX6hNS-VfqGMVM\",\"e\":\"AQAB\",\"kid\":\"4\"}";
const char jwk_privkey_sign_str_2[] = "{\"kty\":\"RSA\",\"n\":\"ALZfFvsvNegnsnjhAydGJ17C9Ny5-M1UqRbcgaPUFRqvfn2P2Yz5rjGTnfFKe9E6xANSNzKRdb5ltNeeJT0inSi2meACAXE68Ud7d2JvlkxQPvz1tJyCKvQFktGwlqwW5F8r_spfT1qJsf_DpZWjsXFrkY7sdrHJdoeQZDIYx0fsGdzlA0uGoGimPlCCExYLcqsjjh3Dqv8V1xJ4jm5S8198v3FJXXm5BN_GWAmExuDOq6ul8MqcECXBQ4LavxFlB5kGgPsxvFjTK72_2YdNDQPkKmV56vShm50BaEqzXU0A2MYeTyabX7d4goI_B7IeX5tGqMjBrlX6hNS-VfqGMVM\",\"e\":\"AQAB\",\"d\":\"HyIUlkT0-vDr8t7W3vmG9xJpItVMuCDfzNtP9lvaTnfvLBhGl154clY0_GAuywUxOS_r5GIYq6xJNxX0XX9vPOgPVMKC5IWfcwiM1O0fx19boWuArcc69fWNnuZ6kl5GFkk4cevbbCVdkcAgoG8Vd7tZWgDcMnWmGnZ35GV-f7Rw3kQTxge4V7T5-I5preMxRAV2YZ1zafIDpYXaOXWL9bX0vAApb5Vie1btPiOj7lZ_J0ChkkdIW-ZTiQZ0sTRo6c6qLVNHQLKAJ_I6QLMfiHAT8xFir3fgiUxNwxxifYOts_akh3-wJEs4r4G92hohmIiIKp2TABDc3WrmFDafYQ\",\"p\":\"ANVUDxAxNuR8Ds5W_3xpGgOKzypYGfimDrU_kRzXsdXOz4EkSYXG2SR7V854vvcgJDzFIihmaI_65LN_pk_6ZE1ddd8Qrud9nMtd5n9neEkOGTCsTO-TM4gLjyZQ3FCo_oCsJ6MiQRlOTw5pf1yH69q3QUd5e_5c75MYr4G0fPwn\",\"q\":\"ANrZ0K-ZdBt9uP1Bt0G7YmW3j41wFt1JnmOkX86YX6Q3wrI4YqiRfolVexAtQ1a1iRVY7ZGXhy_q0rDLPIpfYAy9LSS1NZHb_vu7C-p8hCALxKa6bTGLeT4Z5LABHPBoMVCyKhlANMHhcUeNY76p4JwT1zwT7FIHamKgVKzv_CD1\",\"qi\":\"GUmL7fbgnNa2IQ13i3Xi3A5dXzgqBeVHb2HjAzCJhNCcg8jslpU4rmMoGAq_WagT-U3_NuUVnGWnHTPWHjFe9MkwxPpSIISbMRorOhsZMrlzg4vdyZ2Kt_zs3yNTb_KOYx6YxU3_93IdFU2XjlnUf4mDThVoTSRfNh-NMJgwLUw\",\"dp\":\"ALBi7IGK78RD_0oFDQIlNOkw4NI2PmMliou6n5WlktkiQtiY1GHUZL6Rbay-kcdrwAqvROr6ogJKhMcWCMGgW0bMvCVQeg3WAsr0PR2ixAZDrfhcvtBoefdG93nK6h-XW7ewoKV2MTVnVl6oRDKSACW72DHs9OUAmuaZRqSMQ7uJ\",\"dq\":\"AIgWpDddtB6YOl157Ov6CwD3eVPZXM50RgLuJwmAJREn_3D1sRvjhYz-08zGaLZVoo3cw7YiRNVeL2_yoY3mKwMg7B6EdHBkHhYJRSqmDT8kMj__c4E4mscsMNHlj0pLcEce0yDqlSPu_ZMh7-GTH3HOwKvCM9T6eYQk8SKtBNq1\",\"kid\":\"4\"}";

START_TEST(test_rhonabwy_serialize_se_error)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_UNKNOWN), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0), NULL);
  
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_serialize_se_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_privkey_ecdsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0)), NULL);

  o_free(token);
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_serialize_se_with_key_in_serialize)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_sign_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, jwk_privkey_ecdsa, 0, jwk_pubkey_rsa, 0)), NULL);
  
  o_free(token);
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_serialize_es_error)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_privkey_ecdsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_UNKNOWN), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  ck_assert_ptr_eq(r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0), NULL);
  
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_serialize_es_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, jwk_privkey_ecdsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, NULL, jwk_pubkey_rsa), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN, NULL, 0, NULL, 0)), NULL);
  
  o_free(token);
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_serialize_es_with_key_in_serialize)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_ecdsa, * jwk_pubkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true());
  char * token;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_set_full_claims_json_t(jwt, j_value), RHN_OK);

  ck_assert_int_eq(r_jwt_set_sign_alg(jwt, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_ecdsa, jwk_privkey_sign_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_rsa, jwk_pubkey_rsa_str), RHN_OK);
  
  ck_assert_ptr_ne((token = r_jwt_serialize_nested(jwt, R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN, jwk_privkey_ecdsa, 0, jwk_pubkey_rsa, 0)), NULL);
  
  o_free(token);
  json_decref(j_value);
  r_jwk_free(jwk_privkey_ecdsa);
  r_jwk_free(jwk_pubkey_rsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_error_key)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_error_key_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_error_token_invalid)
{
  jwt_t * jwt;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE_INVALID_CLAIMS_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE_INVALID_DOTS, 0), RHN_ERROR_PARAM);

  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_error_decryption_invalid)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE_INVALID_ENCRYPTION, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_decryption_verify_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_decryption_verify_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_decryption_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  ck_assert_int_eq(r_jwt_decrypt_nested(jwt, jwk_privkey_rsa, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_decryption_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  ck_assert_int_eq(r_jwt_decrypt_nested(jwt, NULL, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_verify_error)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  ck_assert_int_eq(r_jwt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0), RHN_ERROR_PARAM);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_verify_with_add_keys_error)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  ck_assert_int_eq(r_jwt_verify_signature_nested(jwt, NULL, 0), RHN_ERROR_PARAM);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_decryption_then_verify_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  ck_assert_int_eq(r_jwt_decrypt_nested(jwt, jwk_privkey_rsa, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_se_decryption_then_verify_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_SE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT);
  ck_assert_int_eq(r_jwt_decrypt_nested(jwt, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature_nested(jwt, NULL, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_error_key)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str_2), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_error_key_with_add_keys)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey_rsa, * jwk_pubkey_ecdsa;
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);

  ck_assert_int_eq(r_jwt_set_enc_alg(jwt, R_JWA_ALG_RSA1_5), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str_2), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_ERROR_INVALID);
  
  r_jwk_free(jwk_privkey_rsa);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_error_token_invalid)
{
  jwt_t * jwt;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, NULL, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES_INVALID_HEADER_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES_INVALID_CLAIMS_B64, 0), RHN_ERROR_PARAM);
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES_INVALID_DOTS, 0), RHN_ERROR_PARAM);

  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_error_signature_invalid)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES_INVALID_SIGNATURE, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_ERROR_INVALID);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_decryption_verify_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0, jwk_privkey_rsa, 0), RHN_OK);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_decryption_verify_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_OK);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_decryption_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_decrypt_nested(jwt, jwk_privkey_rsa, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_decryption_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_decrypt_nested(jwt, NULL, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_verify_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0), RHN_OK);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_verify_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_verify_signature_nested(jwt, NULL, 0), RHN_OK);

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_verify_then_decryption_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt_nested(jwt, jwk_privkey_rsa, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_verify_then_decryption_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_verify_signature_nested(jwt, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt_nested(jwt, NULL, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_decryption_then_verify_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_decrypt_nested(jwt, jwk_privkey_rsa, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature_nested(jwt, jwk_pubkey_ecdsa, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

START_TEST(test_rhonabwy_nested_es_decryption_then_verify_with_add_keys_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_pubkey_ecdsa, * jwk_privkey_rsa;
  json_t * j_value = json_pack("{sssiso}", "str", "grut", "int", 42, "obj", json_true()), * j_claims;

  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_pubkey_ecdsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_pubkey_ecdsa, jwk_pubkey_sign_str), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_privkey_rsa), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey_rsa, jwk_privkey_rsa_str), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey_rsa, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_pubkey_ecdsa), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt, TOKEN_ES, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_get_type(jwt), R_JWT_TYPE_NESTED_ENCRYPT_THEN_SIGN);
  ck_assert_int_eq(r_jwt_decrypt_nested(jwt, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature_nested(jwt, NULL, 0), RHN_OK);
  ck_assert_ptr_ne(j_claims = r_jwt_get_full_claims_json_t(jwt), NULL);
  ck_assert_int_eq(1, json_equal(j_claims, j_value));

  r_jwt_free(jwt);
  r_jwk_free(jwk_pubkey_ecdsa);
  r_jwk_free(jwk_privkey_rsa);
  json_decref(j_claims);
  json_decref(j_value);
}
END_TEST

/**
 * Valdate the nested JWT in Appendix A.2 of the JWT RFC
 * https://tools.ietf.org/html/rfc7519#appendix-A.2
 */
START_TEST(test_rhonabwy_rfc_ok)
{
  jwt_t * jwt;
  jwk_t * jwk_privkey, * jwk_signkey;
  const char token[] = 
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU"
    "In0."
    "g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"
    "qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"
    "b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"
    "DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"
    "YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq"
    "JGTO_z3Wfo5zsqwkxruxwA."
    "UmVkbW9uZCBXQSA5ODA1Mg."
    "VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"
    "BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"
    "-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"
    "l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"
    "Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"
    "ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"
    "8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"
    "l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"
    "zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"
    "_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ."
    "AVO9iT5AV4CzvDJCdhSFlQ",
  privkey[] = "{\"kty\":\"RSA\","
    "\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl"
    "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre"
    "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_"
    "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI"
    "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU"
    "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\","
    "\"e\":\"AQAB\","
    "\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq"
    "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry"
    "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_"
    "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj"
    "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj"
    "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\","
    "\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68"
    "ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP"
    "krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\","
    "\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y"
    "BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN"
    "-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\","
    "\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv"
    "ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra"
    "Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\","
    "\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff"
    "7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_"
    "odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\","
    "\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC"
    "tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ"
    "B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\""
    "}",
    signkey[] = "{\"kty\":\"RSA\","
      "\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
           "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
           "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
           "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
           "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
           "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\","
      "\"e\":\"AQAB\","
      "\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
           "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
           "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
           "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
           "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
           "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\","
      "\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
           "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
           "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\","
      "\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
           "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
           "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\","
      "\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
           "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
           "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\","
      "\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
           "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
           "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\","
      "\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
           "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
           "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\""
     "}";

  ck_assert_int_eq(r_jwk_init(&jwk_privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_init(&jwk_signkey), RHN_OK);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_privkey, privkey), RHN_OK);
  ck_assert_int_eq(r_jwk_import_from_json_str(jwk_signkey, signkey), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt, jwk_privkey, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk_signkey), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, token, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_decrypt_verify_signature_nested(jwt, NULL, 0, NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_validate_claims(jwt, R_JWT_CLAIM_ISS, "joe", R_JWT_CLAIM_EXP, 1300819370, R_JWT_CLAIM_NOP), RHN_OK);
  ck_assert_ptr_eq(r_jwt_get_claim_json_t_value(jwt, "http://example.com/is_root"), json_true());
  r_jwk_free(jwk_privkey);
  r_jwk_free(jwk_signkey);
  r_jwt_free(jwt);
}
END_TEST

static Suite *rhonabwy_suite(void)
{
  Suite *s;
  TCase *tc_nested;

  s = suite_create("Rhonabwy JWT nested function tests");
  tc_nested = tcase_create("test_rhonabwy_nested");
  tcase_add_test(tc_nested, test_rhonabwy_serialize_se_error);
  tcase_add_test(tc_nested, test_rhonabwy_serialize_se_with_add_keys);
  tcase_add_test(tc_nested, test_rhonabwy_serialize_se_with_key_in_serialize);
  tcase_add_test(tc_nested, test_rhonabwy_serialize_es_error);
  tcase_add_test(tc_nested, test_rhonabwy_serialize_es_with_add_keys);
  tcase_add_test(tc_nested, test_rhonabwy_serialize_es_with_key_in_serialize);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_error_key);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_error_key_with_add_keys);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_error_token_invalid);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_error_decryption_invalid);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_decryption_verify_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_decryption_verify_with_add_keys_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_decryption_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_decryption_with_add_keys_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_verify_error);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_verify_with_add_keys_error);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_decryption_then_verify_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_se_decryption_then_verify_with_add_keys_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_error_key);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_error_key_with_add_keys);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_error_token_invalid);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_error_signature_invalid);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_decryption_verify_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_decryption_verify_with_add_keys_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_decryption_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_decryption_with_add_keys_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_verify_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_verify_with_add_keys_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_verify_then_decryption_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_verify_then_decryption_with_add_keys_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_decryption_then_verify_ok);
  tcase_add_test(tc_nested, test_rhonabwy_nested_es_decryption_then_verify_with_add_keys_ok);
  tcase_add_test(tc_nested, test_rhonabwy_rfc_ok);
  tcase_set_timeout(tc_nested, 30);
  suite_add_tcase(s, tc_nested);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed;
  Suite *s;
  SRunner *sr;
  //y_init_logs("Rhonabwy", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Rhonabwy JWT nested tests");
  r_global_init();
  s = rhonabwy_suite();
  sr = srunner_create(s);

  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  
  r_global_close();
  //y_close_logs();
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
