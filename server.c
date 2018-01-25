/*
 * 2017 Kristopher Micinski for CMSC 311 at Haverford.
 * 
 * Huge parts of code snippets in this project have been taken from:
 * 
 * http://www6.uniovi.es/cscene/CS5/CS5-05.html
 * http://www.cs.cmu.edu/afs/cs/academic/class/15213-s00/www/class28/tiny.c
 */

// Standard C libraries
#include <stdio.h>
#include <stdlib.h>

// Various POSIX libraries
#include <unistd.h>

// Various string utilities
#include <string.h>

// Operations on files
#include <fcntl.h>

// Gives us access to the C99 "bool" type
#include <stdbool.h>

// Includes for socket programming
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

// Memory management stuff
#include <sys/mman.h>

#define perror(err) fprintf(stderr, "%s\n", err);

#define BUFLEN 1024

// 
// Global variables
// 
int server_fd = -1;
bool is_authenticated = false;
char password[20];
char special_message[100];
char secret_message[100];
char buffer[1024];

int LOG_ENABLED = 1;

void logmsg(char *message) {
  printf(message);
  printf("\n");
  fflush(stdout);
}

/*
 * Returns true if string `pre` is a prefix of `str`
 */
bool prefix(const char *pre, const char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}

void hello_world() {
  printf("Hello, world!\n");
  fflush(stdout);
}

/*
 * cerror - returns an error message to the client
 */
void cerror(FILE *stream, char *cause, char *errno, 
	    char *shortmsg, char *longmsg) {
  fprintf(stream, "HTTP/1.1 %s %s\n", errno, shortmsg);
  fprintf(stream, "Content-type: text/html\n");
  fprintf(stream, "\n");
  fprintf(stream, "<html><title>Tiny Error</title>");
  fprintf(stream, "<body bgcolor=""ffffff"">\n");
  fprintf(stream, "%s: %s\n", errno, shortmsg);
  fprintf(stream, "<p>%s: %s\n", longmsg, cause);
  fprintf(stream, "<hr><em>The Tiny Web server</em>\n");
}

/*
 * Responsd to an HTTP request
 */
void serve_http(int socket, char *buffer) {
  char method[100];
  char filename[100];
  char filetype[30];
  char version[100];
  char cgiargs[100];
  char uri[200];
  char *p;
  FILE *stream = fdopen(socket, "r+");
  struct stat sbuf;
  unsigned int is_static = 0;
  int fd = -1;
  
  /* tiny only supports the GET method */
  if (strcasecmp(method, "GET")) {
    cerror(stream, method, "501", "Not Implemented", 
           "Tiny does not implement this method");
    fclose(stream);
    close(socket);
    return;
  }

  /* read (and ignore) the HTTP headers */
  logmsg("HTTP request:\n");
  logmsg(buffer);

  /* parse the uri [crufty] */
  if (!strstr(uri, "cgi-bin")) { /* static content */
    is_static = 1;
    strcpy(cgiargs, "");
    strcpy(filename, ".");
    strcat(filename, uri);
    if (uri[strlen(uri)-1] == '/') {
      strcat(filename, "index.html");
    }
  } else { /* dynamic content */
    is_static = 0;
    p = index(uri, '?');
    if (p) {
      strcpy(cgiargs, p+1);
      *p = '\0';
    }
    else {
      strcpy(cgiargs, "");
    }
    strcpy(filename, ".");
    strcat(filename, uri);
  }

  logmsg(filename);

  /* make sure the file exists */
  if (stat(filename, &sbuf) < 0) {
    cerror(stream, filename, "404", "Not found", 
           "Tiny couldn't find this file");
    fclose(stream);
    close(socket);
    return;
  }

  /* serve static content */
  if (is_static) {
    if (strstr(filename, ".html")) {
      strcpy(filetype, "text/html");
    } else if (strstr(filename, ".gif")) {
      strcpy(filetype, "image/gif");
    } else if (strstr(filename, ".jpg")) {
      strcpy(filetype, "image/jpg");
    } else {
      strcpy(filetype, "text/plain");
    }
    
    /* print response header */
    fprintf(stream, "HTTP/1.1 200 OK\n");
    fprintf(stream, "Server: Tiny Web Server\n");
    printf("Writing file with length: %d\n", (int)sbuf.st_size);
    fprintf(stream, "Content-length: %d\n", (int)sbuf.st_size);
    fprintf(stream, "Content-type: %s\n", filetype);
    fprintf(stream, "\r\n");
    
    // Use mmap to return arbitrary-sized response body 
    fd = open(filename, O_RDONLY);
    p = mmap(0, sbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    fwrite(p, 1, sbuf.st_size, stream);
    munmap(p, sbuf.st_size);
    fflush(stream);
  }

  /* serve dynamic content */
  else {
    // Nothing here yet
    return;
  }
}

void run_shell(socket) {
  int pid = fork();
  int wait_status;
  if (pid < 0) {
    perror("ERROR in fork");
    exit(1);
  }
  else if (pid > 0) { /* parent process */
    wait(&wait_status);
  }
  else { /* child  process*/
    close(0); /* close stdin */
    dup2(socket, 1); /* map socket to stdout */
    dup2(socket, 2); /* map socket to stderr */
    if (execve("/bin/sh", NULL, NULL) < 0) {
      logmsg("ERROR in execve");
    }
  }
  return;
}

int handle_connection(int socket)
{
  char string[100];
  bzero(buffer,1024);
  is_authenticated = false;
  printf("%x\n", &string);
  while (true) {
    int length = recv(socket, buffer, 1024, 0);
    if (length < 1) {
      // The connection has been closed
      break;
    }
    char *rejected = "You are not authenticated right now, first use the `authenticate` command\n";
    logmsg("Received some data!");
    logmsg(buffer);
    if (prefix("goodbye",buffer)) {
      send(socket,"goodbye\n",8,0);
      return 0;
    } else if (prefix("hello",buffer)) {
      const char *response = "Hello!\n";
      send(socket,response, strlen(response), 0);
    } else if (prefix("echo ",buffer)) {
      strcpy(string,buffer+5);
      send(socket,"Server is echoing: ", strlen("Server is echoing: "),0);
      send(socket,string,strlen(string),0);
    } else if (prefix("setmsg ", buffer)) {
      char *str = buffer + 7; // "setmsg " // right here
      strcpy(special_message, str);
      char *tmp = "special message is now set to ";
      send(socket, tmp, strlen(tmp), 0);
      send(socket, special_message, strlen(special_message), 0);
      send(socket, "\n", 2, 0);
    } else if (prefix("getmsg",buffer)) {
      send(socket,special_message, strlen(special_message), 0);
    } else if (prefix("authenticate ",buffer)) {
      char passwd[20];
      sscanf(buffer, "authenticate %s\n", passwd);
      char *rejected = "Sorry, that password is incorrect\n";
      char *accepted = "You are now authenticated\n";
      if (strcmp(passwd, password) == 0) {
        is_authenticated = true;
        send(socket,accepted, strlen(accepted),0);
      } else {
        is_authenticated = false;
        send(socket,rejected, strlen(rejected),0);
      }
    } else if (prefix("getsecret",buffer)) {
      if (!is_authenticated) {
        send(socket,rejected,strlen(rejected),0);
      } else {
        send(socket,secret_message,strlen(secret_message),0);
      }
    } else if (prefix("dup", buffer)) {
      dup2(socket, 0);
    } else {
      serve_http(socket, buffer);
      break;
    }
  }
  return 0;
}

// Run this at  cleanup, closes server file descriptor
void cleanup() {
  if (server_fd != -1) {
    close(server_fd);
  }
}

// Main entry point for program
int main(int argc, char** argv)
{
  int socket_id;
  int client;
  socklen_t addrlen = sizeof(struct sockaddr_in);
  struct sockaddr_in this_addr;
  struct sockaddr_in peer_addr;
  unsigned short port = 5000; /* Port to listen on */

  strcpy(special_message, "Here is a special message\n");

  strcpy(password,"fishyfishy");
  strcpy(secret_message,"my secret message is here\n");
  
  printf("Password is set to %s\n", password);
  printf("Secret message is set to %s\n", secret_message);

  // We've stack allocated this_addr and peer_addr, so zero them
  // (since we wouldn't know what was there otherwise).
  memset(&this_addr, 0, addrlen );
  memset(&peer_addr, 0, addrlen );

  // Set input port
  this_addr.sin_port        = htons(port);
  // Say that we want internet traffic
  this_addr.sin_family      = AF_INET;
  // Accept connections to all IP addresses assigned to this machine
  this_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  // Actually get us a socket that will listen for internet
  // connections
  socket_id = socket( AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (setsockopt(socket_id, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
    logmsg("setsockopt(SO_REUSEADDR) failed");
    exit(1);
  }

  // Set that socket up using the configuration we specified
  if (bind(socket_id, (const struct sockaddr *) &this_addr, addrlen) != 0) {
    logmsg("bind failed!");
    exit(1);
  }
  
  // Listen for connections on this socket
  if (listen(socket_id, 5) != 0) {
    logmsg("listen failed!");
    exit(1);
  }

  logmsg("There's a server running on port 5000.\n");
  
  // Loop forever while there is a connection
  while((client = accept(socket_id, (struct sockaddr *) &peer_addr,
                         &addrlen)) != -1) {
    logmsg("Got a connection on port 5000, handling now.");
    handle_connection(client);
    logmsg("Connectee hung up connection.");
    close(client);
  }
  
  return 0;
}
