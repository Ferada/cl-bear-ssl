#include <unistd.h>
#include <errno.h>

int direct_fd_low_read_callback(void* read_context, unsigned char* data, size_t len) {
  for (;;) {
    ssize_t rlen;

    rlen = read((int)read_context, data, len);
    if (rlen <= 0) {
      if (rlen < 0 && errno == EINTR) {
        continue;
      }
      return -1;
    }
    return (int)rlen;
  }
}

int direct_fd_low_write_callback(void* write_context, const unsigned char* data, size_t len) {
  for (;;) {
    ssize_t wlen;

    wlen = write((int)write_context, data, len);
    if (wlen <= 0) {
      if (wlen < 0 && errno == EINTR) {
        continue;
      }
      return -1;
    }
    return (int)wlen;
  }
}
