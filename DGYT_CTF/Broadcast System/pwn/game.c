#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char xor[1024];

int count;
int node[80];
void *chunk[40];

void init(){
    char data[2048];
    unsigned int byte_count = 1024;
    FILE *fp;

    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);

    fp = fopen("/dev/urandom", "r");
    while(strlen(data) < 1024){
        fread(&data, 1, byte_count, fp);
    }
    fclose(fp);

    memcpy(&xor, &data, 1024);
}

void magic(const void *msg, unsigned int len){
    for(unsigned int i = 0; i < len; i++){
        *(char *)(msg + i) ^= xor[i];
    }
}

void send_con(const void *msg, unsigned int len){
    void *dest;

    dest = malloc(len);
    memcpy(dest, msg, len);

    magic(dest, len - 1);
    write(1, dest, len);
    free(dest);
}

void send_msg(const char *msg){
    unsigned int len;
    
    len = strlen(msg) + 1;
    send_con(msg, len);
}

int recv_num(){
    int res;
    void *buf;

    buf = malloc(8);

    read(0, buf, 8);
    res = atoi(buf);
    free(buf);

    return res;
}

void recv_msg(void *buf, int len){
    unsigned int buf_len;

    buf_len = recv_num();
    if(buf_len > len){
        send_msg("Too long\n");
        exit(0);
    }
    read(0, buf, buf_len);
    magic(buf, buf_len);
    *(char *)(buf + buf_len) = 0;
}

void check(){
    char v[32];

    send_msg("Pwning is awesome~\n");
    recv_msg(&v, 8);

    /*
    if ( 331 * v[6] + 317 * v[5] + 313 * v[4] + 311 * v[3] + 307 * v[2] + 293 * v[1] + 283 * v[0] + 337 * v[7] != 225643
    || 509 * v[6] + 503 * v[5] + 499 * v[4] + 491 * v[3] + 487 * v[2] + 479 * v[1] + 467 * v[0] + 521 * v[7] != 356507
    || 587 * v[6] + 577 * v[5] + 571 * v[4] + 569 * v[3] + 563 * v[2] + 557 * v[1] + 547 * v[0] + 593 * v[7] != 410769
    || 643 * v[6] + 641 * v[5] + 631 * v[4] + 619 * v[3] + 617 * v[2] + 613 * v[1] + 607 * v[0] + 647 * v[7] != 450797
    || 773 * v[6] + 769 * v[5] + 761 * v[4] + 757 * v[3] + 751 * v[2] + 743 * v[1] + 739 * v[0] + 787 * v[7] != 546531
    || 853 * v[6] + 839 * v[5] + 829 * v[4] + 827 * v[3] + 823 * v[2] + 821 * v[1] + 811 * v[0] + 857 * v[7] != 598393
    || 919 * v[6] + 911 * v[5] + 907 * v[4] + 887 * v[3] + 883 * v[2] + 881 * v[1] + 877 * v[0] + 929 * v[7] != 646297
    || 1319 * v[6] + 1307 * v[5] + 1303 * v[4] + 1301 * v[3] + 1297 * v[2] + 1291 * v[1] + 1289 * v[0] + 1321 * v[7] != 935881 )
    */
    
    /*
    if ( 20149 * v7 + 20921 * v6 + 20327 * v[4] + 23911 * v[3] + 18211 * v[2] + 31063 * v[1] + 30971 * v[0] + 17477 * v8 != 14985352
    || 29759 * v7 + 23633 * v6 + 20641 * v[4] + 31121 * v[3] + 16699 * v[2] + 20359 * v[1] + 20051 * v[0] + 25111 * v8 != 14962906
    || 27457 * v7 + 17291 * v6 + 26099 * v[4] + 23333 * v[3] + 25561 * v[2] + 27073 * v[1] + 25943 * v[0] + 30839 * v8 != 16361024
    || 19079 * v7 + 18959 * v6 + 32191 * v[4] + 25411 * v[3] + 29167 * v[2] + 18313 * v[1] + 29873 * v[0] + 16879 * v8 != 14982624
    || 23581 * v7 + 20509 * v6 + 28859 * v[4] + 32441 * v[3] + 19469 * v[2] + 29437 * v[1] + 16607 * v[0] + 26849 * v8 != 16152948
    || 17431 * v7 + 26981 * v6 + 19973 * v[4] + 18869 * v[3] + 26161 * v[2] + 19927 * v[1] + 16823 * v[0] + 26633 * v8 != 14720714
    || 31397 * v7 + 22091 * v6 + 25793 * v[4] + 30577 * v[3] + 28349 * v[2] + 19073 * v[1] + 26821 * v[0] + 26947 * v8 != 16722910
    || 27793 * v7 + 22691 * v6 + 29629 * v[4] + 26183 * v[3] + 30817 * v[2] + 17737 * v[1] + 25339 * v[0] + 19447 * v8 != 15883204 )
    */
    if ( 20327 * v[4] + 23911 * v[3] + 18211 * v[2] + 31063 * v[1] + 30971 * v[0] + 20921 * v[5] + 20149 * v[6] + 17477 * v[7] != 14985352
    || 29759 * v[6] + 23633 * v[5] + 20641 * v[4] + 31121 * v[3] + 16699 * v[2] + 20359 * v[1] + 20051 * v[0] + 25111 * v[7] != 14962906
    || 27457 * v[6] + 17291 * v[5] + 26099 * v[4] + 23333 * v[3] + 25561 * v[2] + 27073 * v[1] + 25943 * v[0] + 30839 * v[7] != 16361024
    || 19079 * v[6] + 18959 * v[5] + 32191 * v[4] + 25411 * v[3] + 29167 * v[2] + 18313 * v[1] + 29873 * v[0] + 16879 * v[7] != 14982624
    || 23581 * v[6] + 20509 * v[5] + 28859 * v[4] + 32441 * v[3] + 19469 * v[2] + 29437 * v[1] + 16607 * v[0] + 26849 * v[7] != 16152948
    || 17431 * v[6] + 26981 * v[5] + 19973 * v[4] + 18869 * v[3] + 26161 * v[2] + 19927 * v[1] + 16823 * v[0] + 26633 * v[7] != 14720714
    || 31397 * v[6] + 22091 * v[5] + 25793 * v[4] + 30577 * v[3] + 28349 * v[2] + 19073 * v[1] + 26821 * v[0] + 26947 * v[7] != 16722910
    || 19447 * v[7] + 27793 * v[6] + 22691 * v[5] + 29629 * v[4] + 26183 * v[3] + 30817 * v[2] + 17737 * v[1] + 25339 * v[0] != 15883204 )
    {
        //printf("Fuck~\n");
        exit(0);
    }
    //printf("Well~\n");
}

void menu(){
    send_msg("Welcome to my magic pwning game\n");
    send_msg("Your choice?\n");
    send_msg("1.add a new node\n");
    send_msg("2.delete a node\n");
    send_msg("3.edit a node\n");
    send_msg("4.show a node\n");
    send_msg("> ");
}

void add(){
    unsigned int size;
    unsigned int index;

    send_msg("Give the node size?\n");
    size = recv_num();
    if(size > 1280){
        send_msg("Too long\n");
        exit(0);
    }

    if(count > 19){
        send_msg("Full\n");
        exit(0);
    }

    node[4 * count] = size;
    index = count;
    chunk[2 * index] = malloc(size);
    count++;
    send_msg("Add done\n");
}

void delete(){
    unsigned int index;

    send_msg("Which node?\n");
    index = recv_num();
    if(index > 19){
        send_msg("Error index\n");
        exit(0);
    }
    if(!chunk[2 * index]){
        send_msg("Error index\n");
        exit(0);
    }
    free(chunk[2 * index]);
    chunk[2 * index] = 0;
    node[4 * index] = 0;
    send_msg("Delete done\n");
}

void edit(){
    unsigned int index;

    send_msg("which node?\n");
    index = recv_num();
    if(index > 19){
        send_msg("Error index\n");
        exit(0);
    }
    if(!chunk[2 * index]){
        send_msg("Error index\n");
        exit(0);
    }
    send_msg("Give the message: ");
    recv_msg(chunk[2 * index], node[4 * index]);
    send_msg("Edit done\n");
}

void show(){
    unsigned int index;

    send_msg("which node?\n");
    index = recv_num();
    if(index > 19){
        send_msg("Error index\n");
        exit(0);
    }
    if(!chunk[2 * index]){
        send_msg("Error index\n");
        exit(0);
    }
    printf("Note %d\n", index);
    puts(chunk[2 * index]);
}

int main(){
    unsigned int key;

    init();
    check();

    while(1){
        menu();
        key = recv_num();
        if(key == 1)
            add();
        else if(key == 2){
            delete();
        }
        else if(key == 3){
            edit();
        }
        else if(key == 4){
            show();
        }
        else{
            send_con("Game over", 5);
            exit(0);
        }
    }

    return 0;
}
