#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

#define INPUT_SIZE 0x20

/* Credential structure */
typedef struct {
  long err;
  char password[INPUT_SIZE];
  char username[INPUT_SIZE];
} cred_t;

/* Root password */
char password[INPUT_SIZE];

void getstr(const char *s, char *buf, size_t len) {
  /* Get a line of input */
  printf("%s", s);
  if (fgets(buf, len, stdin) == NULL)
    exit(1);

  /* Remove trailing newline */
  buf[strlen(buf)-1] = '\0';
}

int main(void) {
  cred_t cred = { .err = -1 };

  /* Ask username and password */
  getstr("Username: ", cred.username, INPUT_SIZE);
  getstr("Password: ", cred.password, INPUT_SIZE);

  /* Authenticate */
  if (strcmp(cred.username, "root") == 0) {
    if (strcmp(cred.password, password) == 0)
      cred.err = 0;
  } else {
    cred.err = -1;
  }

  if (cred.err < 0) {
    puts("[-] Invalid username or password");
  } else {
    puts("[+] Authenticated");
    system("/bin/sh");
  }

  return 0;
}

__attribute__((constructor))
void setup(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  /* Create secure password */
  if (getrandom(password, sizeof(password), 0) != sizeof(password))
    exit(1);

  for (size_t i = 0; i < 9; i++)
    password[i] = 0x21 + ((unsigned char)password[i] % (0x7e - 0x21));
}
