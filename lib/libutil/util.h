/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  UTIL.H
    the common utilities of all files are saved in this file.
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

#ifndef _UTIL_H_
#define _UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------
 * TTY_PRINT() macro
 *---------------------------------------------------*/
#define TTY_PRINT   OSS_PRINT

STATUS  get_local_ip(char *ip_str, char *sif);
STATUS  set_local_ip(char *ip_str, char *sif);

extern char *GetStrTok(char **cpp, char *delimiters);

extern U8	*DECODE_U16(U16 *val, U8 *mp);
extern U8	*DECODE_U24(U32 *val, U8 *mp);
extern U8	*DECODE_U32(U32 *val, U8 *mp);

extern U8	*ENCODE_U16(U8 *mp, U16 val);
extern U8	*ENCODE_U24(U8 *mp, U32 val);
extern U8	*ENCODE_U32(U8 *mp, U32 val);

extern void PRINT_MESSAGE(unsigned char*, int);
extern U16 	ADD_CARRY_FOR_CHKSUM(U32 sum);
extern U16 	CHECK_SUM(U32);
extern void OSS_PRINT(const char *, ...);

#ifdef __cplusplus
}
#endif

#endif
