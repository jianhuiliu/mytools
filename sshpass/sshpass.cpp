/**
 * Copyright (C) 2012, by ChinaMobile & GBase
 * All rights reserved.
 *
 * @file        sshpass.cpp
 * @description 该文件由开源程序sshpass移植而来
 *
 * @author      liujianhui
 * @date        
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#if HAVE_TERMIOS_H
#include <termios.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>
enum program_return_codes {
    RETURN_NOERROR,
    RETURN_INVALID_ARGUMENTS,
    RETURN_CONFLICTING_ARGUMENTS,
    RETURN_RUNTIME_ERROR,
    RETURN_PARSE_ERRROR,
    RETURN_INCORRECT_PASSWORD,
    RETURN_HOST_KEY_UNKNOWN,
    RETURN_HOST_KEY_CHANGED,
};
enum PWT_TYPE{
    PWT_STDIN, 
    PWT_FILE,
    PWT_FD,
    PWT_PASS
};

// Some systems don't define posix_openpt
#ifndef HAVE_POSIX_OPENPT
    int
posix_openpt(int flags)
{
    return open("/dev/ptmx", flags);
}
#endif

int runprogram( int argc, char *argv[],char*result,int len);

struct _ARGS{
    PWT_TYPE pwtype;
    union PWT_SRC{
        const char *filename;
        int fd;
        const char *password;
    } pwsrc;
} args;

/**
 * @brief       get ssh command result
 * @note        调用 runprogram函数执行shell命令
 * @param       [in]password,执行命令主机的密码
 * @param       [in]cmd,shell命令
 * @param       [out]result,shell命令执行结果
 * @param       [in]len,result长度
 * @returns     执行成功返回0，其他返回失败
 * @exception
 */
int getSSHCmdResult(const char*const password,const char*const cmd,char*result,int len)
{
    //save password into args
    const char split = NULL;
    if(password == NULL)
    {
        printf("please input the  password for node\n");
        return -1;
    }
    args.pwtype=PWT_PASS;
    args.pwsrc.password=strdup(password);


    //split cmd into tokens by space
    if(cmd == NULL)
    {
        printf("please input the shell command\n");
        return -1;
    }
    char *tokens[24]={NULL};

    int i = 0;
    if(split == NULL)
    {
        tokens[i] = strtok(strdup(cmd)," ");
        while(tokens[++i]=strtok(NULL," "));
    }else
    {
        tokens[i] = strtok(strdup(cmd),split);
        while(tokens[++i]=strtok(NULL,split));
    }

    //call runprogram to execute cmd
    return runprogram( i, tokens,result,len);
}


/**
 * @brief       run shell command
 * @note        调用 runprogram函数执行shell命令
 * @param       [in]password,执行命令主机的密码
 * @param       [in]cmd,shell命令
 * @param       [in]split,shell命令
 * @returns     执行成功返回0，其他返回失败
 * @exception
 */
int runSSHCmd(const char*const password,const char*const cmd,char*split=NULL)
{
    //save password into args
    if(password == NULL)
    {
        printf("please input the  password for node\n");
        return -1;
    }
    args.pwtype=PWT_PASS;
    args.pwsrc.password=strdup(password);


    //split cmd into tokens by space
    if(cmd == NULL)
    {
        printf("please input the shell command\n");
        return -1;
    }
    char *tokens[24]={NULL};

    int i = 0;
    if(split == NULL)
    {
        tokens[i] = strtok(strdup(cmd)," ");
        while(tokens[++i]=strtok(NULL," "));
    }else
    {
        tokens[i] = strtok(strdup(cmd),split);
        while(tokens[++i]=strtok(NULL,split));
    }
    //call runprogram to execute cmd
    return runprogram( i, tokens,NULL,0);
}

int handleoutput( int fd,char*result,int len);

/* Global variables so that this information be shared with the signal handler */
static int ourtty; // Our own tty
static int masterpt;

void window_resize_handler(int signum);
void sigchld_handler(int signum);



/**
 * @brief       call ssh run shell command
 * @note        the code is copied form open program "sshpass"
 * @param       argc,the paragram number
 * @param       argv,the point of point of cmd
 * @returns     0 sucess ,other failed
 * @exception
 */
int runprogram( int argc, char *argv[],char*result,int len)
{
    int ii = 0;

    struct winsize ttysize; // The size of our tty

    // We need to interrupt a select with a SIGCHLD. In order to do so, we need a SIGCHLD handler
    signal( SIGCHLD,sigchld_handler );

    // Create a pseudo terminal for our process
    masterpt=posix_openpt(O_RDWR);

    if( masterpt==-1 ) {
        perror("Failed to get a pseudo terminal");

        return RETURN_RUNTIME_ERROR;
    }

    fcntl(masterpt, F_SETFL, O_NONBLOCK);

    if( grantpt( masterpt )!=0 ) {
        perror("Failed to change pseudo terminal's permission");

        return RETURN_RUNTIME_ERROR;
    }
    if( unlockpt( masterpt )!=0 ) {
        perror("Failed to unlock pseudo terminal");

        return RETURN_RUNTIME_ERROR;
    }

    ourtty=open("/dev/tty", 0);
    if( ourtty!=-1 && ioctl( ourtty, TIOCGWINSZ, &ttysize )==0 ) {
        signal(SIGWINCH, window_resize_handler);

        ioctl( masterpt, TIOCSWINSZ, &ttysize );
    }

    const char *name=ptsname(masterpt);
    int slavept;
    /*
       Comment no. 3.14159

       This comment documents the history of code.

       We need to open the slavept inside the child process, after "setsid", so that it becomes the controlling
       TTY for the process. We do not, otherwise, need the file descriptor open. The original approach was to
       close the fd immediately after, as it is no longer needed.

       It turns out that (at least) the Linux kernel considers a master ptty fd that has no open slave fds
       to be unused, and causes "select" to return with "error on fd". The subsequent read would fail, causing us
       to go into an infinite loop. This is a bug in the kernel, as the fact that a master ptty fd has no slaves
       is not a permenant problem. As long as processes exist that have the slave end as their controlling TTYs,
       new slave fds can be created by opening /dev/tty, which is exactly what ssh is, in fact, doing.

       Our attempt at solving this problem, then, was to have the child process not close its end of the slave
       ptty fd. We do, essentially, leak this fd, but this was a small price to pay. This worked great up until
       openssh version 5.6.

       Openssh version 5.6 looks at all of its open file descriptors, and closes any that it does not know what
       they are for. While entirely within its prerogative, this breaks our fix, causing sshpass to either
       hang, or do the infinite loop again.

       Our solution is to keep the slave end open in both parent AND child, at least until the handshake is
       complete, at which point we no longer need to monitor the TTY anyways.
       */

    int childpid=fork();
    if( childpid==0 ) {
        // Child

        // Detach us from the current TTY
        setsid();
        // This line makes the ptty our controlling tty. We do not otherwise need it open
        slavept=open(name, O_RDWR );
        dup2(slavept,STDIN_FILENO);
        dup2(slavept,STDOUT_FILENO);
        dup2(slavept,STDERR_FILENO);

        close( masterpt );

        char **new_argv=(char**)malloc(sizeof(char *)*(argc+1));

        int i;

        for( i=0; i<argc; ++i ) {
            new_argv[i]=argv[i];
        }

        new_argv[i]=NULL;

        execvp( new_argv[0], new_argv );

        perror("sshpass: Failed to run command");

        close( slavept );
        exit(RETURN_RUNTIME_ERROR);
    } else if( childpid<0 ) {
        perror("sshpass: Failed to create child process");

        return RETURN_RUNTIME_ERROR;
    }

    // We are the parent
    //slavept=open(name, O_RDWR|O_NOCTTY );

    int status=0;
    int terminate=0;
    pid_t wait_id;
    sigset_t sigmask, sigmask_select;

    // Set the signal mask during the select
    sigemptyset(&sigmask_select);

    // And during the regular run
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);

    sigprocmask( SIG_SETMASK, &sigmask, NULL );

    do {
        if( !terminate ) {
            fd_set readfd;

            FD_ZERO(&readfd);
            FD_SET(masterpt, &readfd);

            int selret=pselect( masterpt+1, &readfd, NULL, NULL, NULL, &sigmask_select );

            if( selret>0 ) {
                if( FD_ISSET( masterpt, &readfd ) ) {
                    int ret;
                    if( (ret=handleoutput( masterpt,result,len)) ) {
                        // Authentication failed or any other error

                        // handleoutput returns positive error number in case of some error, and a negative value
                        // if all that happened is that the slave end of the pt is closed.
                        if( ret>0 ) {
                            close( masterpt ); // Signal ssh that it's controlling TTY is now closed
                        }

                        terminate=ret;

                        if( terminate ) {
                        }
                    }
                }
            }
            wait_id=waitpid( childpid, &status, WNOHANG );
        } else {
            wait_id=waitpid( childpid, &status, 0 );
        }
    } while( wait_id==0 || (!WIFEXITED( status ) && !WIFSIGNALED( status )) );

    if( terminate>0 )
        return terminate;
    else if( WIFEXITED( status ) )
        return WEXITSTATUS(status);
    else
        return 255;
}

int match( const char *reference, const char *buffer, ssize_t bufsize, int state );
void write_pass( int fd );

int handleoutput( int fd,char*result,int len)
{
    // We are looking for the string
    int prevmatch=0; // If the "password" prompt is repeated, we have the wrong password.
    int state1 =0, state2=0,state3=0;
    const char compare1[]="assword:"; // Asking for a password
    const char compare2[]="The authenticity of host "; // Asks to authenticate host
    const char compare3[]="\n"; // Asks to authenticate host
    // static const char compare3[]="WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"; // Warns about man in the middle attack
    // The remote identification changed error is sent to stderr, not the tty, so we do not handle it.
    // This is not a problem, as ssh exists immediately in such a case
    char buffer[1024];
    int ret=0;
    memset(buffer,0,1024);
    int numread=read(fd, buffer, sizeof(buffer) );
    // Are we at a password prompt?
    state1=match( compare1, buffer, numread, state1 );
    if( compare1[state1]=='\0' ) 
    {
        if( !prevmatch ) {
            write_pass( fd );
            state1=0;
            prevmatch=1;
            return ret;
        } else {
            // Wrong password - terminate with proper error code
            return RETURN_INCORRECT_PASSWORD;
        }
    }

    state2=match( compare2, buffer, numread, state2 );
    // Are we being prompted to authenticate the host?
    if( compare2[state2]=='\0' ) {
        write( fd, "yes", strlen( "yes" ) );
        write( fd, "\n", 1 );
        return ret;
    }

    if(numread ==2){
        state3=match(compare3,buffer,numread, state3 );
        if(compare3[state3]=='\0'){
            return ret;
        }
    }
    
    if((numread >0)&&(result != NULL))
    {
        memset(result,0,len);
        int length = (numread <len)? numread:len;
        sprintf(result,buffer,length);
    }
    return ret;
}

int match( const char *reference, const char *buffer, ssize_t bufsize, int state )
{
    // This is a highly simplisic implementation. It's good enough for matching "Password: ", though.
    int i;
    for( i=0;reference[state]!='\0' && i<bufsize; ++i ) 
    {
        if( reference[state]==buffer[i] )
        {
            state++;
        }
        else 
        {
            state=0;
            if( reference[state]==buffer[i] )
            {
                state++;
            }
        }
    }
    return state;
}

void write_pass_fd( int srcfd, int dstfd );

void write_pass( int fd )
{
    switch( args.pwtype ) {
        case PWT_STDIN:
            write_pass_fd( STDIN_FILENO, fd );
            break;
        case PWT_FD:
            write_pass_fd( args.pwsrc.fd, fd );
            break;
        case PWT_FILE:
            {
                int srcfd=open( args.pwsrc.filename, O_RDONLY );
                if( srcfd!=-1 ) {
                    write_pass_fd( srcfd, fd );
                    close( srcfd );
                }
            }
            break;
        case PWT_PASS:
            write( fd, args.pwsrc.password, strlen( args.pwsrc.password ) );
            write( fd, "\n", 1 );
            break;
    }
}

void write_pass_fd( int srcfd, int dstfd )
{
    int done=0;
    while( !done ) {
        char buffer[40];
        int i;
        int numread=read( srcfd, buffer, sizeof(buffer) );
        done=(numread<1);
        for( i=0; i<numread && !done; ++i ) {
            if( buffer[i]!='\n' )
                write( dstfd, buffer+i, 1 );
            else
                done=1;
        }
    }
    write( dstfd, "\n", 1 );
}

void window_resize_handler(int signum)
{
    struct winsize ttysize; // The size of our tty

    if( ioctl( ourtty, TIOCGWINSZ, &ttysize )==0 )
        ioctl( masterpt, TIOCSWINSZ, &ttysize );
}

// Do nothing handler - makes sure the select will terminate if the signal arrives, though.
void sigchld_handler(int signum)
{
}
int test_main(int argc,char**argv)
{
     runSSHCmd("centos","ssh root@192.168.152.150 service rdbware status");
     char result[1024]={0};
     getSSHCmdResult("centos","ssh root@192.168.152.150 service rdbware status",result,1024);
     printf("%s\n",result);
}
