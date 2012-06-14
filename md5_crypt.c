#include <string.h>
#include "md5.h"

static unsigned char itoa64[] = /* 0 ... 63 => ascii - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void to64(char *s, unsigned long v, int n)
{
        while (--n >= 0) {
                *s++ = itoa64[v & 0x3f];
                v >>= 6;
        }
}


char *crypt_md5(const char *password, const char *salt)
{
	char passwd[256];
	const char *magic = "$1$";
	md5_state_t state;
	md5_state_t state1;
	md5_byte_t digest[16];
	int pl;
	int i,j;
	char *p;
	unsigned long l;

	bf_md5_init(&state);
	bf_md5_append(&state, (const md5_byte_t *)password, strlen(password));
	bf_md5_append(&state, (const md5_byte_t *)magic, strlen(magic));
	bf_md5_append(&state, (const md5_byte_t *)salt, strlen(salt));

	/* Then just as many characters of the MD5(pw,salt,pw) */
	bf_md5_init(&state1);
	bf_md5_append(&state1,(const md5_byte_t *)password, strlen(password));
	bf_md5_append(&state1, (const md5_byte_t *)salt, strlen(salt));
	bf_md5_append(&state1,(const md5_byte_t *)password, strlen(password));
	bf_md5_finish(&state1, digest);
	
        for (pl = strlen(password); pl > 0; pl -= 16)
                bf_md5_append(&state,(const md5_byte_t *)digest,pl>16 ? 16 : pl);
	
        /* Don't leave anything around in vm they could use. */
        memset(digest, 0, sizeof digest);

        /* Then something really weird... */
        for (j = 0, i = strlen(password); i; i >>= 1)
                if (i & 1)
			bf_md5_append(&state, (const md5_byte_t *)digest+j, 1);
		else
			bf_md5_append(&state, (const md5_byte_t *)password+j, 1);

	/* Now make the output string */
        strcpy(passwd, magic);
	strncat(passwd, salt, strlen(salt));
	strcat(passwd, "$");

	bf_md5_finish(&state, digest);
	
	for (i = 0; i < 1000; i++) {
		bf_md5_init(&state1);
                if (i & 1)
			bf_md5_append(&state1,(const md5_byte_t *)password, strlen(password));
                else
			bf_md5_append(&state1, (const md5_byte_t *)digest, 16);

                if (i % 3)
			bf_md5_append(&state1, (const md5_byte_t *)salt, strlen(salt));

                if (i % 7)
			bf_md5_append(&state1,(const md5_byte_t *)password, strlen(password));

                if (i & 1)
			bf_md5_append(&state1, (const md5_byte_t *)digest, 16);
                else
			bf_md5_append(&state1,(const md5_byte_t *)password, strlen(password));
		bf_md5_finish(&state1, digest);
        }

        p = passwd + strlen(passwd);

        l = (digest[0] << 16) | (digest[6] << 8) | digest[12];
        to64(p, l, 4);
        p += 4;
        l = (digest[1] << 16) | (digest[7] << 8) | digest[13];
        to64(p, l, 4);
        p += 4;
        l = (digest[2] << 16) | (digest[8] << 8) | digest[14];
        to64(p, l, 4);
        p += 4;
        l = (digest[3] << 16) | (digest[9] << 8) | digest[15];
        to64(p, l, 4);
        p += 4;
        l = (digest[4] << 16) | (digest[10] << 8) | digest[5];
        to64(p, l, 4);
        p += 4;
        l = digest[11];
        to64(p, l, 2);
        p += 2;
        *p = '\0';

        memset(digest, 0, sizeof digest);

        return strdup(passwd);
}
