#define MIN(a,b) (((a)<(b))?(a):(b))
#define bpdump(p,n) 1

#undef strlcpy
size_t strlcpy(char *, const char *, size_t);

void weprintf(const char *, ...);
void eprintf(const char *, ...);
void enprintf(int, const char *, ...);
