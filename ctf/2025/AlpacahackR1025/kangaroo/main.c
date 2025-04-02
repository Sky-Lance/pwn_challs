#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLOT 8
#define SIZE 0x48

char g_messages[SLOT*SIZE];
void (*fn_clear)(void*, size_t);

static void clear_message(void *buf, size_t len) {
  memset(buf, 0, len);
}

off_t get_offset(const char *s) {
  off_t offset;
  ssize_t index;

  printf("%s", s);
  if (scanf("%ld", &index) != 1)
    exit(1);

  if (index >= LLONG_MAX / SIZE) {
    puts("[-] Integer overflow");
    exit(1);
  }

  offset = index * SIZE;
  if (offset < 0 || offset >= sizeof(g_messages)) {
    puts("[-] Invalid offset");
    exit(1);
  }

  return offset;
}

void read_line(const char *s, char *buf, size_t n) {
  printf("%s", s);
  for (size_t i = 0; i < n; i++) {
    if (read(0, buf + i, 1) != 1) exit(1);
    if (buf[i] == '\n') {
      buf[i] = '\0';
      break;
    }
  }
}

int main() {
  off_t offset;
  int choice;

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  fn_clear = clear_message;

  puts("1. Read\n2. Write\n3. Clear");
  while (1) {
    printf("> ");
    if (scanf("%d", &choice) != 1)
      break;

    switch (choice) {
      case 1: // Read
        offset = get_offset("Index: ");
        read_line("Message: ", g_messages + offset, SIZE);
        break;

      case 2: // Write
        offset = get_offset("Index: ");
        printf("Message: %s\n", g_messages + offset);
        break;

      case 3: // Clear
        fn_clear(g_messages, sizeof(g_messages));
        break;

      default:
        return 0;
    }
    
  }
  return 0;
}
