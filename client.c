#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#define BUF_SIZE 65535

// Resource Record Types
#define A_Resource_RecordType 1
#define CNAME_Resource_RecordType 5
#define MX_Resource_RecordType 15
#define PTR_Resource_RecordType 12
#define NS_Resource_RecordType 2

// Class
#define IN_Class 1
#define CH_Class 3
#define HS_Class 4

// Response Type
#define Ok_ResponseType 0
#define FormatError_ResponseType 1
#define ServerFailure_ResponseType 2
#define NameError_ResponseType 3
#define NotImplemented_ResponseType 4
#define Refused_ResponseType 5


//用于保存packet中出现的第一个域名的字节码和它相对于header的位置
//只保存整个packet里的第一个域名，不考虑第二个域名、第三个域名能否用来当做压缩参照的情况
//考虑那些的话难度实在太大了，压缩指针这块甚至还可以嵌套，太难实现
struct CompressPointerInfo {
    unsigned char* name;
    uint8_t pos;
};

//用于将一个域名存储为一段一段的，如“15邮箱服务器6北邮6教育6中国0”在以下结构体中存储，将会是一个三项的链表：
//name=“邮箱服务器”，len=15，next=北邮的指针，
//name=“北邮”，len=6，next=教育的指针，
//……
//最后的0不会被存在这个结构体里
struct DomainName {
    unsigned char* name;
    uint8_t len;
    struct DomainName* next;//单向链表
};

//用来存储packet中所携带的question
struct Question {
    struct DomainName* name;
    unsigned short type;
    unsigned short class;
    struct Question* next;
};

//用一个union去存储Resource Record中的具体Data
//union就是我向系统请求一片内存空间，这片空间的类型还不确定，但肯定是某几个类型中的一个
//所以就用一个union把所有类型都列出来，申请内存的时候按最大的那个可能去申
//然后我再读取再写入信息
union ResourceData {
    struct {
        uint8_t addr[4];
    } a_record;
    struct {
        unsigned short preference;
        unsigned char* exchange;
    } mx_record;
    struct {
        unsigned char* name;
    } cname_record;
    struct {
        unsigned char* name;
    } ptr_record;
    struct {
        unsigned char* name;
    } ns_record;
};

// Resource Record 结构体，其中域名是已经经过函数解析成链表的，而非原本的字节码
struct ResourceRecord {
    struct DomainName* name;
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rd_length;
    union ResourceData rd_data;
    struct ResourceRecord* next;
};

//程序收到packet后会先将packet字节码转换成这个Message结构体
//在构造response的时候也是先生成这个Message结构体，然后再转换成packet字节码
struct Message {
    unsigned short id;

    //header
    unsigned short qr; // Query/Response Flag
    unsigned short opcode; // Operation Code
    unsigned short aa; // Authoritative Answer Flag
    unsigned short tc; // Truncation Flag
    unsigned short rd; // Recursion Desired
    unsigned short ra; // Recursion Available
    unsigned short rcode; // Response Code
    unsigned short qCount; // Question Count
    unsigned short ansCount; // Answer Record Count
    unsigned short auCount; // Authority Record Count
    unsigned short adCount; // Additional Record Count

    struct Question* questions;
    struct ResourceRecord* answers;
    struct ResourceRecord* authorities;
    struct ResourceRecord* additionals;
};

// Masks 用于读取和写入header，因为C语言的>>和<<的操作特点
//左移是逻辑/算术左移(两者完全相同),右移是算术右移,会保持符号位不变
//特别是右移的这个特性，所以用这个MASK把不需要的位数特别是符号位给清理掉比较妥当
unsigned int QR_MASK = 0x8000;
unsigned int OPCODE_MASK = 0x7800;
unsigned int AA_MASK = 0x0400;
unsigned int TC_MASK = 0x0200;
unsigned int RD_MASK = 0x0100;
unsigned int RA_MASK = 0x0080;
unsigned int RCODE_MASK = 0x000F;

unsigned char* resolveFile;//存储已知域名解析的文件
unsigned char* serverFile;//存储权威服务器地址的文件
unsigned char* myIpAddr;//服务器要绑定的ip地址
int isLocal;//服务器是不是local server，如果是local server，它在serverFile里没找到最佳匹配的话会去询问根。如果不是local server，找不到匹配就返回空了
int isRecursive;//是否递归，递归实质上和所有的服务器都是local server相似，但递归服务器不会在找不到最佳匹配的情况下去问根

//一个用来保存当前任务的链表，声明成全局的比较方便
//如同一个packet携带了多个需要去解决的question
//或者一个question需要迭代/递归地去解析，那么就需要用到这么一个链表去存储正在解析和接下来需要解析的域名
struct Question* taskList;

//内存操作，从buffer中读取1个字节的内容，并将buffer的指针向后移动一位，方便继续读取
//为什么是**buffer呢，因为如果是buffer，那它就是一个普通的变量，你用这个函数修改它只在这个函数内生效，并不能做到移动指针的效果。
//如果是*buffer，它是一个指针，你修改它，出了函数就不生效了，如果你修改*buffer的*，那么你只会把它指向的内容修改，比如从ASCII的“a”+1变成了“b”，而不是移动指针。
//如果是**buffer，它是一个指针的指针，这样你修改了*buffer，才是修改了指针，才能做到把指针往后移动一位的效果。
uint8_t get8bits(uint8_t** buffer) {
    uint8_t value;
    memcpy(&value, *buffer, 1);
    *buffer += 1;
    //大端小端问题只有在表示的数据类型大于一个字节的时候存在，所以在这个函数中不需要考虑此问题，直接返回value即可
    return value;
}

//内存操作，从buffer中读取2个字节的内容，并将buffer的指针向后移动2位
unsigned short get16bits(uint8_t** buffer) {
    unsigned short value;
    memcpy(&value, *buffer, 2);
    *buffer += 2;
    //大于一个字节的数据类型需要考虑大小端转换问题
    return ntohs(value);
}

//内存操作，从buffer中读取4个字节的内容，好像只有ttl用到了
//并将buffer的指针向后移动4位
unsigned int get32bits(uint8_t** buffer) {
    unsigned int value;

    memcpy(&value, *buffer, 4);
    *buffer += 4;
    //大于一个字节的数据类型需要考虑大小端转换问题
    return ntohl(value);
}

//内存操作，将1个字节写入buffer，并将buffer的指针向后移动一位
void put8bits(uint8_t** buffer, uint8_t value) {
    //一个字节无需大小端转换
    memcpy(*buffer, &value, 1);
    *buffer += 1;
}

//内存操作，将2个字节写入buffer，并将buffer的指针向后移动2位
void put16bits(uint8_t** buffer, unsigned short value) {
    value = htons(value);//大小端转换
    memcpy(*buffer, &value, 2);
    *buffer += 2;
}

//内存操作，将4个字节写入buffer，并将buffer的指针向后移动4位
void put32bits(uint8_t** buffer, unsigned int value) {
    value = htonl(value);//大小端转换
    memcpy(*buffer, &value, 4);
    *buffer += 4;
}

//删除DomaiName链表，清理内存
void freeDomainName(struct DomainName* dn) {
    struct DomainName* next;
    while (dn) {
        if (dn->name != NULL) {
            //free(dm->name);//有bug，先注释掉，会导致一些内存不被释放，运行时间久了占内存会越来越大，不过这只是一个运行几分钟的大作业而已不会有啥问题……
        }
        next = dn->next;
        free(dn);
        dn = next;
    }
}

//删除ResourceRecord链表，清理内存
void freeResourceRecords(struct ResourceRecord* rr) {
    struct ResourceRecord* next;
    while (rr) {
        freeDomainName(rr->name);
        next = rr->next;
        free(rr);
        rr = next;
    }
}

//删除Question链表，清理内存
void freeQuestions(struct Question* q) {
    struct Question* next;
    while (q) {
        freeDomainName(q->name);
        next = q->next;
        free(q);
        q = next;
    }
}

//将一个域名从15邮箱服务器6北邮6教育6中国0的字节码转换为邮箱服务器.北邮.教育.中国的字符串
unsigned char* domainBytes2DomainStr(unsigned char* domain) {
    uint8_t* buf = domain;
    int i=0, j=0, len=0;
    unsigned char* name;
    name = malloc(sizeof(unsigned char)*BUF_SIZE);
    memset(name,0,sizeof(unsigned char)*BUF_SIZE);

    while (buf[i] != 0) {
        if (i != 0) {
            strncat(name, ".", 1);
            j++;
        }

        len = buf[i];
        i++;

        memcpy(name+j, buf+i, len);
        i += len;
        j += len;
    }

    name[j] = '\0';

    return strdup(name);//复制这个字符串并返回复制的字符串的指针。之所以要复制这个字符串，是因为C语言同一个函数再次被调用的时候，变量们很大可能会使用跟上次一模一样的内存空间，这样的话上次运行此函数产生的结果就会被覆盖，所以需要把字符串复制一遍，返回这个复制体的指针。
}

//从北邮.教育.中国的字符串转换为6北邮6教育6中国0的字节码
unsigned char* domainStr2DomainBytes(unsigned char* domain) {
    unsigned char* buf;
    buf = malloc(sizeof(unsigned char)*BUF_SIZE);
    memset(buf,0,sizeof(unsigned char)*BUF_SIZE);
    unsigned char* beg = domain;
    unsigned char* pos;
    int i = 0, len = 0;

    while ((pos = strchr(beg, '.'))) {
        len = pos - beg;
        buf[i] = len;
        i++;
        memcpy(buf+i, beg, len);
        i += len;
        beg = pos + 1;
    }

    len = strlen(domain) - (beg - domain);
    buf[i] = len;
    i ++;
    memcpy(buf + i, beg, len);
    i += len;
    buf[i] = 0;

    return strdup(buf);
}


//将字节码倒置后转换为DomainName结构体链表
//倒置是因为在比较域名是否匹配时，需要从后段开始匹配
//如北邮.教育.中国，需要先看中国，再看教育，最后看北邮，所以不如存成结构体的时候就倒过来存，方便比较
//参数中的header是用于解压域名中的压缩指针的
//因为压缩指针是指向某个域名第一次出现时相对于header的位置偏移，所以需要header的地址来做参照
//压缩指针是一段两个字节长的内容，其中前两个bit是1，后面是长度，如果只有前两个bit是1，后面都是0的话，那么就是c000，
//一般长度不会特别长，所以往往压缩指针是c0xx这样的。
//另外，记得这种实现方式不支持嵌套指针。
struct DomainName* domainBytes2DomainStructureFromPacket(uint8_t** buffer, uint8_t* header) {
    uint8_t* buf = *buffer;
    int i, j, first;
    uint8_t len = 0;
    struct DomainName* name = NULL;
    name = malloc(sizeof(struct DomainName));
    memset(name, 0, sizeof(struct DomainName));
    struct DomainName* head = name;//最终返回的是这个head，因为过程中name在变
    unsigned char* nameStr;

    //用于将字节码反转的变量
    uint8_t* bufNew;
    uint8_t** reverse;
    uint8_t lenReverse;
    uint8_t* tempReverse;
    int lenNew;
    reverse = (uint8_t**)malloc(sizeof(uint8_t*) * BUF_SIZE);

    //用于解压缩的变量
    uint8_t* bufExpress;
    int compressPointer = 0;//用来存储压缩指针，注意这个压缩指针不是C语言中的指针而是DNS的指针，它是一个相对于header首字节的位置偏移，所以用int类型存储就可以了
    uint8_t* copyPointer;//用来存储接下来该读内存的哪里的指针
    bufExpress = malloc(sizeof(uint8_t)*BUF_SIZE);
    memset(bufExpress, 0, sizeof(uint8_t)*BUF_SIZE);
    int bufferMoved = 0;//用来记录buffer到底移动了多少，在别的函数中你读取了多少字节buffer就应该移动多少字节，但是在压缩指针这里，一旦遇到压缩指针，buffer的位移就跟读取的字节数不相等了
    int bufExpressLen = 0;//记录buf_express到底读了多长，也就用于最后给末尾补0

    copyPointer = buf;

    //开始解压缩
    i = 0;
    while (copyPointer[i]!=0) {
        if (copyPointer[i]>=0xc0) {//大于c0则此处和下一个字节加起来是一个指针
            compressPointer = copyPointer[i]*(16*16)+copyPointer[i+1]-0xc0*(16*16);//16*16是位移两个字节
            copyPointer = header + compressPointer;
            bufferMoved += i + 2;//2为压缩指针的字节数，这种写法只适合没有嵌套指针的情况
            i = 0;//因为copyPointer变了，又得从那个指针位置之后的0点开始读起了所以需要把i重置为0
        }
        len = copyPointer[i];
        memcpy(bufExpress+bufExpressLen,copyPointer+i,1);
        i++;
        bufExpressLen++;
        memcpy(bufExpress+bufExpressLen,copyPointer+i,len);
        i += len;
        bufExpressLen += len;
    }
    bufExpress[bufExpressLen] = 0;

    //开始反向存储，即字节码6北邮6教育6中国->6中国6教育6北邮，
    //反向存储就是先分段存一个数组里，再倒过来从这个数组里取拼成一个字符串
    bufNew = malloc(sizeof(uint8_t)*(strlen(bufExpress)+1));//因为strlen计算出的长度不包括最后的0所以需要+1
    memset(bufNew, 0, sizeof(uint8_t)*(strlen(bufExpress)+1));
    i = 0;
    j = 0;
    while (bufExpress[i] != 0) {
        lenReverse = bufExpress[i];
        tempReverse = malloc(sizeof(uint8_t)*(lenReverse+1+1));//开头的长度和结尾的\0
        memset(tempReverse, 0, sizeof(uint8_t)*(lenReverse+1+1));
        tempReverse[0] = bufExpress[i];
        i++;
        memcpy(tempReverse + 1, bufExpress + i, lenReverse);
        reverse[j] = tempReverse;
        i += lenReverse;
        j++;
    }

    lenNew = 0;
    for(i = j - 1; i >= 0; i--) {
        memcpy(bufNew + lenNew, reverse[i], strlen(reverse[i]));
        lenNew += strlen(reverse[i]);
    }

    //开始将字节码存成链表
    first = 1;
    i = 0;
    while (bufNew[i] != 0) {
        if (!first) {
            name->next = malloc(sizeof(struct DomainName));
            memset(name->next, 0, sizeof(struct DomainName));
            name = name->next;
        }
        first = 0;
        len = bufNew[i];
        i++;
        nameStr = malloc(sizeof(unsigned char)*(len+1));
        memset(nameStr, 0, sizeof(unsigned char)*(len+1));
        memcpy(nameStr, bufNew+i, len);
        nameStr[len] = '\0';
        name->name = nameStr;
        name->len = len;
        i += len;
    }
    if (bufferMoved!=0)
        *buffer += bufferMoved;
    else
        *buffer += i + 1; //+1为最后的0

    name->next = NULL;
    return head;
}

//跟上面那个函数基本一样，区别是输入源是一段字符串因此不需要移动buffer，而且肯定不会遇到压缩指针
struct DomainName* domainBytes2DomainStructureFromStr(uint8_t* buffer) {
    uint8_t* buf = buffer;
    int i, j, first;
    uint8_t len = 0;
    struct DomainName* name = NULL;
    name = malloc(sizeof(struct DomainName));
    memset(name, 0, sizeof(struct DomainName));
    struct DomainName* head = name;
    unsigned char* nameStr;

    //用于将字节码反转的变量
    uint8_t* bufNew;
    uint8_t** reverse;
    uint8_t lenReverse;
    uint8_t* tempReverse;
    int lenNew;
    reverse = (uint8_t**)malloc(sizeof(uint8_t*) * BUF_SIZE);

    bufNew = malloc(sizeof(uint8_t)*strlen(buf)+1);//最后的\0
    memset(bufNew, 0, sizeof(uint8_t)*strlen(buf)+1);
    i = 0;
    j = 0;
    while (buf[i] != 0) {
        lenReverse = buf[i];
        tempReverse = malloc(sizeof(uint8_t)*(lenReverse+1+1));
        memset(tempReverse, 0, sizeof(uint8_t)*(lenReverse+1+1));
        tempReverse[0] = buf[i];
        i++;
        memcpy(tempReverse + 1, buf + i, lenReverse);
        reverse[j] = tempReverse;
        i += lenReverse;
        j += 1;
    }

    lenNew = 0;
    for(i = j - 1; i >= 0; i--) {
        memcpy(bufNew + lenNew, reverse[i], strlen(reverse[i]));
        lenNew += strlen(reverse[i]);
    }

    first = 1;
    i = 0;
    while (bufNew[i] != 0) {
        if (!first) {
            name->next = malloc(sizeof(struct DomainName));
            memset(name->next, 0, sizeof(struct DomainName));
            name = name->next;
        }
        first = 0;
        len = bufNew[i];
        i++;
        nameStr = malloc(sizeof(unsigned char)*(len+1));
        memset(nameStr, 0, sizeof(unsigned char)*(len+1));
        memcpy(nameStr, bufNew+i, len);
        nameStr[len] = '\0';
        name->name = nameStr;
        name->len = len;
        i += len;
    }

    name->next = NULL;
    return head;
}

//将DomainName链表写入buffer
//参数中包含CompressPointerInfo结构体和header指针，用于DNS的压缩指针
void putDomainName2Buffer(uint8_t** buffer, struct DomainName* domainName, struct CompressPointerInfo* domainNameStr, uint8_t* header) {
    uint8_t* buf = *buffer;
    uint8_t* bufOrig;
    uint8_t* bufNew;
    struct DomainName* domain = domainName;
    int len;
    int i,j;
    uint8_t** reverse;
    uint8_t len_reverse;
    uint8_t* temp_reverse;
    int lengthNew = 0;
    int position = -1;
    int position2 = -1;
    unsigned char* substring;
    unsigned char* substring2;
    int hasCPflag = 0;

    //读一遍长度，就是为了后面分配内存。。。
    len = 0;
    while (domain->next != NULL) {
        len++;
        len+=domain->len;
        domain = domain->next;
    }
    len++;
    len+=domain->len;
    len++;

    bufOrig = malloc(sizeof(uint8_t)*len);
    memset(bufOrig,0,sizeof(uint8_t)*len);
    domain = domainName;

    i = 0;

    while (domain->next != NULL) {
        bufOrig[i] = domain->len;
        i++;
        memcpy(bufOrig+i,domain->name,domain->len);
        i+=domain->len;
        domain = domain->next;
    }
    bufOrig[i] = domain->len;
    i++;
    memcpy(bufOrig+i,domain->name,domain->len);

    i = 0;
    j = 0;
    bufNew = malloc(sizeof(uint8_t)*(len+1));
    memset(bufNew, 0, sizeof(uint8_t)*(len+1));
    reverse = (uint8_t**)malloc(sizeof(uint8_t*) * BUF_SIZE);

    //开始反向
    while (bufOrig[i] != 0) {
        len_reverse = bufOrig[i];

        temp_reverse = malloc(sizeof(uint8_t)*(len_reverse+1+1));//一个是开头的长度，另一个是字符串结尾的\0
        memset(temp_reverse, 0, sizeof(uint8_t)*(len_reverse+1+1));
        temp_reverse[0] = bufOrig[i];
        i += 1;
        memcpy(temp_reverse + 1, bufOrig + i, len_reverse);
        reverse[j] = temp_reverse;
        i += len_reverse;
        j += 1;
    }
    for(i = j - 1; i >= 0; i--) {
        memcpy(bufNew + lengthNew, reverse[i], strlen(reverse[i]));
        lengthNew += strlen(reverse[i]);
    }

    //开始压缩指针
    if(domainNameStr!=NULL) {
        if(domainNameStr->pos!=0) {
            hasCPflag = 1;
        }
    }
    if(hasCPflag) {
        substring = domainNameStr->name;
        while (substring[0]!='\0') {
            substring2 = strstr(bufNew,substring);
            if (substring2!=NULL) {
                position = strlen(domainNameStr->name)-strlen(substring2);
                position2 = strlen(bufNew)-strlen(substring2);
                break;
            } else {
                substring += (uint8_t)substring[0]+1;
            }
        }
    }
    else if (header!=NULL) {
        //如果header不是null却没有cp，那么就是希望现在将当前的domainName填入cp里
        domainNameStr->name = strdup(bufNew);
        domainNameStr->pos = *buffer - header;
    }
    if (position>=0 && position2>=0) {
        memcpy(buf, bufNew, position2);//position2是子串在原字符串的相对位置，也就是长度
        *buffer += position2;
        int fields = 0;
        fields |= (1 << 15) & 0x8000;
        fields |= (1 << 14) & 0x4000;
        fields += domainNameStr->pos+position;//指针真正指向的位置，是原本的pos加上position偏移
        put16bits(buffer,fields);
    }
    else {
        memcpy(buf, bufNew, len);
        buf[len] = 0;
        *buffer += len;
    }
}

//用于MX、CNAME以及可能的NS、PTR，和上面的类似，将域名存入buffer，不同的是参数是一个已经整理好的6北邮6教育6中国的字节码而非结构体，
//且具有返回值，是长度，因为可能会用上压缩指针导致长度发生变化
int putDomainNameOfRD2Buffer(uint8_t** buffer, unsigned char* bufNew, struct CompressPointerInfo* cp, uint8_t* header) {
    uint8_t* buf = *buffer;
    int len = strlen(bufNew)+1;

    int position = -1;
    int position2 = -1;
    unsigned char* substring;
    unsigned char* substring2;

    int hasCPflag = 0;
    if(cp!=NULL){
        if(cp->pos!=0) {
            hasCPflag = 1;
        }
    }
    if(hasCPflag) {
        substring = cp->name;
        while (substring[0]!='\0') {
            substring2 = strstr(bufNew,substring);
            if (substring2!=NULL) {
                position = strlen(cp->name)-strlen(substring2);
                position2 = strlen(bufNew)-strlen(substring2);
                break;
            } else {
                substring += (uint8_t)substring[0]+1;
            }
        }
    }
    else if (header!=NULL) {
        //如果header不是null却没有cp，那么就是希望现在将当前的domainName填入cp里
        cp->name = strdup(bufNew);
        cp->pos = *buffer - header;
    }

    if (position>=0 && position2>=0) {
        memcpy(buf, bufNew, position2);//position2是子串在原字符串的相对位置，也就是长度
        *buffer += position2;
        int fields = 0;
        fields |= (1 << 15) & 0x8000;
        fields |= (1 << 14) & 0x4000;
        fields += cp->pos+position;//指针真正指向的位置，是原本的pos加上position偏移
        put16bits(buffer,fields);
        return position2+2;//2是fields的长度，也就是压缩指针的长度
    }
    else {
        memcpy(buf, bufNew, len);
        buf[len] = 0;
        *buffer += len;
        return len;
    }
}

unsigned char* domainStructure2DomainBytes(struct DomainName* domainName) {
    struct DomainName* domain = domainName;
    unsigned char* nameStr;
    nameStr = malloc(sizeof(unsigned char)*BUF_SIZE);
    memset(nameStr, 0, sizeof(unsigned char)*BUF_SIZE);
    unsigned char* origNameStr = nameStr;//指针的原位置，因为putDomainName2Buffer函数会移动指针
    putDomainName2Buffer(&nameStr, domain, NULL, NULL);//这个函数在将domain写入nameStr的时候，会移动nameStr的指针的位置
    return origNameStr;
}


unsigned char* getDomainNameStr(struct DomainName* domainName) {
    return strdup(domainBytes2DomainStr(domainStructure2DomainBytes(domainName)));
}

void printRR(struct ResourceRecord* rr) {
    int i;
    while (rr) {
        printf("RR 名称:%s，类型:%u，类别:%u，TTL:%d，rd_length:%u，",
               getDomainNameStr(rr->name),
               rr->type,
               rr->class,
               rr->ttl,
               rr->rd_length
        );
        union ResourceData* rd = &rr->rd_data;
        switch (rr->type) {
            case A_Resource_RecordType:
                printf("A address:");
                for(i = 0; i < 4; ++i)
                    printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);
                printf("\n");
                break;
            case CNAME_Resource_RecordType:
                printf("CNAME name:%s\n", getDomainNameStr(domainBytes2DomainStructureFromStr(rd->cname_record.name)));
                break;
            case PTR_Resource_RecordType:
                printf("PTR name:%s\n", rd->ptr_record.name);
                break;
            case MX_Resource_RecordType:
                printf("MX preference:%u exchange:%s\n", rd->mx_record.preference, getDomainNameStr(domainBytes2DomainStructureFromStr(rd->mx_record.exchange)));
                break;
            default:
                printf("未知类型\n");
        }
        rr = rr->next;
    }
}

void printMessage(struct Message* msg) {
    printf("请求ID: %02x，", msg->id);
    printf("问题数: %u，", msg->qCount);
    printf("回答数: %u，", msg->ansCount);
    printf("权威服务器数: %u，", msg->auCount);
    printf("附加数: %u\n", msg->adCount);
    printf("\n");
    struct Question* q = msg->questions;
    while (q) {
        printf("问题:名称:%s，", getDomainNameStr(q->name));
        printf("类型:%u，",q->type);
        printf("类别:%u\n",q->class);
        q = q->next;
    }
    if(msg->ansCount>0) {
        printf("\n回答:\n");
        printRR(msg->answers);
    }
    if(msg->auCount>0) {
        printf("\n权威服务器:\n");
        printRR(msg->authorities);
    }

    if(msg->adCount>0) {
        printf("\n附加:\n");
        printRR(msg->additionals);
    }
}

void writeRR(struct ResourceRecord* rr, uint8_t** buffer, struct CompressPointerInfo* cp, uint8_t* header) {
    int i,new_rd_length;
    uint8_t* rd_length_pos;
    while (rr) {
        putDomainName2Buffer(buffer, rr->name, cp, header);
        put16bits(buffer, rr->type);
        put16bits(buffer, rr->class);
        put32bits(buffer, rr->ttl);
        rd_length_pos = *buffer;
        put16bits(buffer, rr->rd_length);

        switch (rr->type) {
            case A_Resource_RecordType:
                for(i = 0; i < 4; ++i)
                    put8bits(buffer, rr->rd_data.a_record.addr[i]);
                break;
            case MX_Resource_RecordType:
                put16bits(buffer,rr->rd_data.mx_record.preference);
                new_rd_length = putDomainNameOfRD2Buffer(buffer, rr->rd_data.mx_record.exchange, cp, header);
                put16bits(&rd_length_pos,new_rd_length+2);//2为preference长度
                break;
            case CNAME_Resource_RecordType:
                new_rd_length = putDomainNameOfRD2Buffer(buffer, rr->rd_data.cname_record.name, cp, header);
                put16bits(&rd_length_pos,new_rd_length);
                break;
            default:
                fprintf(stderr, "未知类型 %u, 忽略\n", rr->type);
                break;
        }
        rr = rr->next;
    }
}

void writeHeader(struct Message* msg, uint8_t** buffer) {
    put16bits(buffer, msg->id);
    int fields = 0;
    fields |= (msg->qr << 15) & QR_MASK;
    fields |= (msg->aa << 10) & AA_MASK;
    fields |= (msg->rd << 8) & RD_MASK;
    fields |= (msg->ra << 7) & RA_MASK;
    fields |= (msg->rcode << 0) & RCODE_MASK;
    put16bits(buffer, fields);
    put16bits(buffer, msg->qCount);
    put16bits(buffer, msg->ansCount);
    put16bits(buffer, msg->auCount);
    put16bits(buffer, msg->adCount);
}


void readSection(struct Message* msg, uint8_t** buffer, int section, unsigned short count, uint8_t* header) {
    if (count<=0)
        return;
    int i,j;
    struct ResourceRecord* rr;
    for (i = 0; i < count; ++i) {
        rr = malloc(sizeof(struct ResourceRecord));
        memset(rr, 0, sizeof(struct ResourceRecord));
        rr->name = domainBytes2DomainStructureFromPacket(buffer, header);
        rr->type = get16bits(buffer);
        rr->class = get16bits(buffer);
        rr->ttl = get32bits(buffer);
        rr->rd_length = get16bits(buffer);
        switch (rr->type) {
            case A_Resource_RecordType:
                for(j = 0; j < 4; ++j)
                    rr->rd_data.a_record.addr[j] = get8bits(buffer);
                break;

            case MX_Resource_RecordType:
                rr->rd_data.mx_record.preference = get16bits(buffer);
                rr->rd_data.mx_record.exchange = domainStructure2DomainBytes(
                        domainBytes2DomainStructureFromPacket(buffer, header));
                break;

            case CNAME_Resource_RecordType:
                rr->rd_data.cname_record.name = domainStructure2DomainBytes(
                        domainBytes2DomainStructureFromPacket(buffer, header));
                break;

            default:
                fprintf(stderr, "未知类型 %u, 忽略\n", rr->type);
                break;
        }
        if (section == 1) {
            rr->next = msg->answers;
            msg->answers = rr;
        }
        else if (section == 2) {
            rr->next = msg->authorities;
            msg->authorities = rr;
        }
        else if (section == 3) {
            rr->next = msg->additionals;
            msg->additionals = rr;
        }
    }
}

void readQuestion(struct Message* msg, uint8_t** buffer, uint8_t* header) {
    int i;
    for (i = 0; i < msg->qCount; ++i) {
        struct Question* q;
        q = malloc(sizeof(struct Question));
        memset(q, 0, sizeof(struct Question));
        q->name = domainBytes2DomainStructureFromPacket(buffer, header);
        q->type = get16bits(buffer);
        q->class = get16bits(buffer);
        q->next = msg->questions;
        msg->questions = q;
    }
}

void readHeader(struct Message* msg, uint8_t** buffer) {
    msg->id = get16bits(buffer);
    unsigned int fields = get16bits(buffer);
    msg->qr = (fields & QR_MASK) >> 15;
    msg->opcode = (fields & OPCODE_MASK) >> 11;
    msg->aa = (fields & AA_MASK) >> 10;
    msg->tc = (fields & TC_MASK) >> 9;
    msg->rd = (fields & RD_MASK) >> 8;
    msg->ra = (fields & RA_MASK) >> 7;
    msg->rcode = (fields & RCODE_MASK) >> 0;
    msg->qCount = get16bits(buffer);
    msg->ansCount = get16bits(buffer);
    msg->auCount = get16bits(buffer);
    msg->adCount = get16bits(buffer);
}

void writeBuffer(struct Message* msg, uint8_t** buffer) {
    put16bits(buffer, 0);//TCP header 长度占位
    struct Question* q;
    uint8_t* header = *buffer;
    struct CompressPointerInfo cp;
    writeHeader(msg, buffer);
    q = msg->questions;
    while (q) {
        putDomainName2Buffer(buffer, q->name, &cp, header);
        put16bits(buffer, q->type);
        put16bits(buffer, q->class);
        q = q->next;
    }
    writeRR(msg->answers, buffer, &cp, header);
    writeRR(msg->authorities, buffer, &cp, header);
    writeRR(msg->additionals, buffer, &cp, header);
}

void readBuffer(struct Message* msg, uint8_t* buffer) {
    get16bits(&buffer);//TCP header 长度
    uint8_t* header = buffer;
    readHeader(msg, &buffer);
    readQuestion(msg, &buffer, header);
    readSection(msg, &buffer, 1, msg->ansCount, header);
    readSection(msg, &buffer, 2, msg->auCount, header);
    readSection(msg, &buffer, 3, msg->adCount, header);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("使用说明: %s <服务器IP> <域名> <类型> ...... \n", argv[0]);
        printf("如: %s 127.0.0.1 北邮.教育.中国 A 北邮.教育.中国 MX 教育.中国 CNAME ...\n", argv[0]);
        exit(1);
    }

    struct timeval start, end;
    struct sockaddr_in srvAddr;
    unsigned short srvPort = 53;
    int sock;
    int qCount;
    int bufLen;
    struct Message msg;
    struct Question* q;
    uint8_t* pointerForWrite;
    uint8_t* pointerForLength;
    unsigned char* srvIp = argv[1];
    uint8_t buffer[BUF_SIZE];

    gettimeofday( &start, NULL );
    srand(1000000*start.tv_sec+start.tv_usec);
    memset(&msg, 0, sizeof(struct Message));
    memset(&buffer,0,sizeof(buffer));

    msg.id = rand()%65535;
    msg.qr = 0;
    msg.aa = 0;
    msg.rd = 0;
    msg.ra = 0;
    msg.rcode = 0;
    msg.qCount = 0;
    msg.ansCount = 0;
    msg.auCount = 0;
    msg.adCount = 0;

    for(qCount=2;qCount<argc;qCount+=2) {
        msg.qCount++;
        q = malloc(sizeof(struct Question));
        memset(q, 0, sizeof(struct Question));
        q->name = domainBytes2DomainStructureFromStr(domainStr2DomainBytes(argv[qCount]));
        if (strcmp(argv[qCount+1],"A")==0)
            q->type = A_Resource_RecordType;
        else if (strcmp(argv[qCount+1],"NS")==0)
            q->type = NS_Resource_RecordType;
        else if (strcmp(argv[qCount+1],"MX")==0)
            q->type = MX_Resource_RecordType;
        else if (strcmp(argv[qCount+1],"CNAME")==0)
            q->type = CNAME_Resource_RecordType;
        else {
            printf("unsupported type, exit!\n");
            exit(1);
        }
        q->class = IN_Class;
        q->next = msg.questions;
        msg.questions = q;
    }
    pointerForWrite = buffer;
    printf("*************************************\n");//此处的printf非常重要，不可删除
    //海森堡观察者效应bug，必须在这个writeBuffer前面加一行printf才能跑通。。。
    writeBuffer(&msg, &pointerForWrite);

    bufLen = pointerForWrite - buffer;
    pointerForLength = buffer;
    put16bits(&pointerForLength, bufLen-2);//填充header应写入的长度

    memset(&srvAddr, 0, sizeof(srvAddr));

    srvAddr.sin_family = AF_INET;
    srvAddr.sin_addr.s_addr = inet_addr(srvIp);
    srvAddr.sin_port = htons(srvPort);

    sock = socket(PF_INET, SOCK_STREAM, 0);
    connect(sock, (struct sockaddr *) &srvAddr, sizeof(srvAddr));

    if (send(sock, buffer, bufLen, 0) != bufLen) {
        printf("sendto() sent a different number of bytes than expected.\n");
        close(sock);
        exit(1);
    }
    freeQuestions(msg.questions);
    freeResourceRecords(msg.answers);
    freeResourceRecords(msg.authorities);
    freeResourceRecords(msg.additionals);
    memset(&msg, 0, sizeof(struct Message));
    memset(&buffer,0,sizeof(buffer));
    recv(sock,buffer,sizeof(buffer),0);
    readBuffer(&msg, buffer);
    printMessage(&msg);
    gettimeofday(&end, NULL );
    int timeuse = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;
    printf("time: %d us\n", timeuse);

    close(sock);
    exit(0);
}
