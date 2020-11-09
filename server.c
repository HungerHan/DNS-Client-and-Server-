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
unsigned char* cacheFile;//存储缓存解析结果的文件
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

//在从文件里读取的一整行内容中读取到两个分隔符之间的一个内容，并把指针后移
unsigned char* readOnePartFromLine(unsigned char** buffer) {
    unsigned char* buf = *buffer;
    unsigned char* pos;
    unsigned char* temp;
    int len = 0;
    pos = strchr(buf,'\t');//在字符串中找到分隔符
    if (pos == NULL)
        return 0;//没有找到分隔符
    len = pos - buf;//通过两个指针相减得到长度
    temp = malloc(len+sizeof(unsigned char));//其实len+1应该也可以，需要加这么一个是为了存字符串末尾的\0
    memset(temp, 0, len+sizeof(unsigned char));//置0内存
    memcpy(temp, buf, len);//拷入数据
    temp[len]='\0';//加上\0
    *buffer += len + 1;//跳过数据的len那么长以及后面的一个分隔符
    return temp;
}

//在从文件里读取的一整行内容中读取到一个ip的一段，并把指针后移
unsigned char* readOnePartOfIP(unsigned char** buffer) {
    unsigned char* buf = *buffer;
    unsigned char* pos;
    unsigned char* temp;
    int len = 0;
    pos = strchr(buf,'.');
    if (pos == NULL)
        return buf;//找不到分隔符，那就应该是最后一段了，直接返回这段的指针
    len = pos - buf;
    temp = malloc(len+sizeof(unsigned char));
    memset(temp, 0, len+sizeof(unsigned char));
    memcpy(temp, buf, len);
    temp[len]='\0';
    *buffer += len + 1;
    return temp;
}

//读取一行中的最后一段，分隔符是\n
unsigned char* readLastPartFromLine(unsigned char** buffer) {
    unsigned char* buf = *buffer;
    unsigned char* pos;
    unsigned char* temp;
    int len = 0;
    pos = strchr(buf,'\n');
    if (pos == NULL)
        return 0;
    len = pos - buf;
    temp = malloc(len+sizeof(unsigned char));
    memset(temp, 0, len+sizeof(unsigned char));
    memcpy(temp, buf, len);
    temp[len]='\0';
    *buffer += len + 1;
    return temp;
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
    reverse = (uint8_t**)malloc(sizeof(uint8_t*) * 10);//一个域名最长不会有10段吧

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
                printf("未知类型 %u, 忽略\n", rr->type);
                break;
        }
        rr = rr->next;
    }
}

void writeHeader(struct Message* msg, uint8_t** buffer) {
    put16bits(buffer, msg->id);
    if(msg->ansCount+msg->auCount+msg->adCount<=0)
        msg->rcode = NameError_ResponseType;
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
                printf("未知类型 %u, 忽略\n", rr->type);
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
    uint8_t* header = buffer;
    readHeader(msg, &buffer);
    readQuestion(msg, &buffer, header);
    readSection(msg, &buffer, 1, msg->ansCount, header);
    readSection(msg, &buffer, 2, msg->auCount, header);
    readSection(msg, &buffer, 3, msg->adCount, header);
}

//从文件里读取信息
//返回有-1、1、2，-1为未找到，1为有最佳匹配，2为有完全匹配
//从文件中查找类型、class完全一致的，以及域名最佳匹配或完全匹配的条目，并把它的信息写入rr结构体中
//用了两个DomainName结构体来存储目标域名和读取域名，来判断它们是否匹配
int getRecordFromFile(struct ResourceRecord* rr, struct DomainName* targetDomainName, unsigned char* fileName) {
    unsigned char* type;
    unsigned char* class;
    FILE* fd = NULL;
    unsigned char* buf;
    int bufsize = BUF_SIZE;
    int bestMatchCount = 0;
    int hasBestMatch = 0;
    int gotTarget = 0;
    int matchCount = 0;
    int len, count;
    int lineDomainReachEnd = 0;
    int compareResult;
    struct DomainName* domainNamePos;
    struct DomainName* domainName2;
    struct DomainName* domainName2head;
    unsigned char* edgePos;
    unsigned char* bufDomain;

    switch (rr->type) {
        case A_Resource_RecordType:
            type = "A";
            break;
        case NS_Resource_RecordType:
            type = "NS";
            break;
        case CNAME_Resource_RecordType:
            type = "CNAME";
            break;
        case PTR_Resource_RecordType:
            type = "PTR";
            break;
        case MX_Resource_RecordType:
            type = "MX";
            break;
        default:
            type = "A";
    }
    switch (rr->class) {
        case IN_Class:
            class = "IN";
            break;
        case CH_Class:
            class = "CH";
            break;
        case HS_Class:
            class = "HS";
            break;
        default:
            class = "IN";
    }
    fd = fopen(fileName, "r");
    buf = malloc(sizeof(unsigned char)*BUF_SIZE);
    memset(buf, 0, sizeof(unsigned char)*BUF_SIZE);
    while(fgets(buf,bufsize,fd)>0) {
        if (strlen(buf)<5)
            continue;
        unsigned char* origBufPos = buf;
        if (strcmp(type,readOnePartFromLine(&buf))==0) {//第一次得到的是type
            if (strcmp(class,readOnePartFromLine(&buf))==0) {//第二次得到的是class
                domainNamePos = targetDomainName;
                matchCount = 0;
                lineDomainReachEnd = 0;

                edgePos = strchr(buf,'\t');
                len = edgePos - buf;
                count = len;
                bufDomain = malloc(sizeof(unsigned char)*(len+1));//1为\0预留
                memset(bufDomain, 0, sizeof(unsigned char)*(len+1));
                memcpy(bufDomain, buf, len);//bufDomain=北邮.教育.中国\t
                domainName2 = domainBytes2DomainStructureFromStr(domainStr2DomainBytes(bufDomain));
                domainName2head = domainName2;

                buf += count + 1;//跳过分隔符
                while (1) {
                    if (domainName2 == NULL || domainNamePos == NULL)
                        break;
                    if (domainName2->next == NULL )
                        lineDomainReachEnd = 1;//已达到从文件读取的域名的末尾，可以开始计算最佳/完全匹配。如果没有达到末尾，不能计算匹配，因为南邮.教育.中国不能匹配北邮.教育.中国
                    compareResult = strcmp(domainNamePos->name,domainName2->name);
                    if ( compareResult != 0 )
                        break;
                    matchCount += 1;
                    if (lineDomainReachEnd) {
                        if (matchCount > bestMatchCount) {
                            if (domainNamePos->next == NULL)
                                gotTarget = 1;
                            rr->name = domainName2head;
                            bestMatchCount = matchCount;
                            hasBestMatch = 1;
                            if (rr->type == CNAME_Resource_RecordType) {
                                unsigned char* nameOfCNAME = readOnePartFromLine(&buf);
                                rr->ttl = atol(readLastPartFromLine(&buf));
                                rr->rd_data.cname_record.name = domainStr2DomainBytes(nameOfCNAME);
                                rr->rd_length = strlen(rr->rd_data.cname_record.name)+1;//+1为\0预留
                            }
                            else if (rr->type == MX_Resource_RecordType) {
                                unsigned char* nameOfMX = readOnePartFromLine(&buf);
                                unsigned char* bufMX = nameOfMX;
                                unsigned char* posMX;
                                int lenMX = 0;

                                posMX = strchr(bufMX,',');//根据逗号分割，取前半部分为邮件服务器域名，取后半部分为preference
                                lenMX = posMX - bufMX;
                                nameOfMX = malloc(lenMX + sizeof(unsigned char));
                                memset(nameOfMX, 0, lenMX + sizeof(unsigned char));
                                memcpy(nameOfMX, bufMX, lenMX);
                                nameOfMX[lenMX]='\0';
                                bufMX += lenMX + 1;//跳过分隔符
                                rr->rd_data.mx_record.preference = atoi(bufMX);
                                rr->ttl = atol(readLastPartFromLine(&buf));
                                rr->rd_data.mx_record.exchange = domainStr2DomainBytes(nameOfMX);
                                rr->rd_length = strlen(rr->rd_data.mx_record.exchange) + 1 + 2;//+1为域名字节码末尾的0，+2为preference固定的2字节
                            }
                            else {
                                unsigned char* addr = rr->rd_data.a_record.addr;
                                unsigned char* ipAddr = readOnePartFromLine(&buf);
                                rr->ttl = atol(readLastPartFromLine(&buf));
                                rr->rd_length = 4;
                                addr[0] = atoi(readOnePartOfIP(&ipAddr));
                                addr[1] = atoi(readOnePartOfIP(&ipAddr));
                                addr[2] = atoi(readOnePartOfIP(&ipAddr));
                                addr[3] = atoi(readOnePartOfIP(&ipAddr));
                            }
                        }
                        break;
                    }
                    domainNamePos = domainNamePos->next;
                    domainName2 = domainName2->next;
                }
            }
        }
        buf = origBufPos;
    }
    fclose(fd);
    if (gotTarget)
        return 2;
    if (hasBestMatch)
        return 1;
    return -1;
}

//将得到的结果存入缓存文件
//只存和请求的内容一模一样的返回结果，或者如果forceSave是1，那么所有结果都存
//同时统计请求的内容是否在返回结果里，如果在，返回值是1
int saveRecord2File(struct ResourceRecord* rr, struct DomainName* query_domain, unsigned char* fileName, int queryType, int forceSave) {
    FILE* fd = NULL;
    unsigned char* buf;
    unsigned char* line2Save;
    unsigned char* line2Search;
    unsigned char* type;
    unsigned char* class;
    unsigned char* rrResult;
    int bufSize = BUF_SIZE;
    int hasTask = 0;
    int found = 0;

    fd = fopen(fileName, "r+");
    buf = malloc(sizeof(unsigned char)*BUF_SIZE);
    memset(buf, 0, sizeof(unsigned char)*BUF_SIZE);

    line2Save = malloc(sizeof(unsigned char)*BUF_SIZE);
    memset(line2Save, 0, sizeof(unsigned char)*BUF_SIZE);

    line2Search = malloc(sizeof(unsigned char)*BUF_SIZE);
    memset(line2Search, 0, sizeof(unsigned char)*BUF_SIZE);

    while(rr) {
        if ((strcmp(getDomainNameStr(rr->name), getDomainNameStr(query_domain))==0 && queryType==rr->type) || forceSave == 1) {
            hasTask = 1;
            switch (rr->type) {
                case A_Resource_RecordType:
                    type = "A";
                    break;
                case NS_Resource_RecordType:
                    type = "NS";
                    break;
                case CNAME_Resource_RecordType:
                    type = "CNAME";
                    break;
                case PTR_Resource_RecordType:
                    type = "PTR";
                    break;
                case MX_Resource_RecordType:
                    type = "MX";
                    break;
                default:
                    type = "A";
            }
            switch (rr->class) {
                case IN_Class:
                    class = "IN";
                    break;
                case CH_Class:
                    class = "CH";
                    break;
                case HS_Class:
                    class = "HS";
                    break;
                default:
                    class = "IN";
            }


            rrResult = malloc(sizeof(unsigned char)*BUF_SIZE);
            memset(rrResult, 0, sizeof(unsigned char)*BUF_SIZE);

            switch (rr->type) {
                case A_Resource_RecordType:
                    sprintf(rrResult,"%u.%u.%u.%u",
                            rr->rd_data.a_record.addr[0],
                            rr->rd_data.a_record.addr[1],
                            rr->rd_data.a_record.addr[2],
                            rr->rd_data.a_record.addr[3]
                            );
                    break;
                case CNAME_Resource_RecordType:
                    sprintf(rrResult,"%s", getDomainNameStr(domainBytes2DomainStructureFromStr(rr->rd_data.cname_record.name)));
                    break;
                case MX_Resource_RecordType:
                    sprintf(rrResult,"%s,%u", getDomainNameStr(domainBytes2DomainStructureFromStr(rr->rd_data.mx_record.exchange)),rr->rd_data.mx_record.preference);
                    break;
                default:
                    printf("Unknown Resource Record");
            }

            sprintf(line2Save,"%s\t%s\t%s\t%s\t%d\n",type,class, getDomainNameStr(rr->name),rrResult,rr->ttl);
            sprintf(line2Search,"%s\t%s\t%s",type,class, getDomainNameStr(rr->name));

            while(fgets(buf,bufSize,fd)>0) {
                unsigned char* origBufPos = buf;
                if (strlen(buf)<5) {//如果buf太小，则此行无效，跳过。5这个数随便写的
                    memset(buf, 0, sizeof(unsigned char)*BUF_SIZE);
                    continue;
                }
                if (strstr(buf,line2Search)!=0) {
                    found = 1;
                    break;
                }
                buf = origBufPos;
                memset(buf, 0, sizeof(unsigned char)*BUF_SIZE);
            }
            if (found == 0) {
                fputs(line2Save,fd);
            } else {
                //此处应该考虑把旧的缓存删掉，把新的缓存写入进去
                //但是C语言删改文件太麻烦了，还是算了= =
            }
        }
        rewind(fd);//回到文件的开头
        rr = rr->next;
    }
    fclose(fd);
    return hasTask;
}

//用于生成找到的最佳匹配的链表
//finalDomainName是查找最佳匹配时匹配失败的那一段，因此我们应该复制这一段之前的所有段
//这个函数的使用场景是，finalDomainName是targetDomainName这个链表中的一项，因此当next为finalDomainName时停止复制。
//当finalDomainName是NULL时，这个函数可以用来完全复制一个DomainName链表
struct DomainName* getBestMatchDomainName(struct DomainName* targetDomainName, struct DomainName* finalDomainName) {
    struct DomainName* readFromTarget = targetDomainName;
    struct DomainName* name;
    struct DomainName* head; //因为在代码运行过程中name不断被name->next替代，所以需要一个变量记录head的地址
    unsigned char* name_str;

    int first = 1;
    name = malloc(sizeof(struct DomainName));
    memset(name, 0, sizeof(struct DomainName));
    head = name;
    while (readFromTarget->next != finalDomainName) {
        if (!first) {
            name->next = malloc(sizeof(struct DomainName));
            memset(name->next, 0, sizeof(struct DomainName));
            name = name->next;
            readFromTarget = readFromTarget->next;
        }
        name_str = malloc(sizeof(unsigned char)*(readFromTarget->len+1));//+1是为了字符串最后的\0
        memset(name_str, 0, sizeof(unsigned char)*(readFromTarget->len+1));
        memcpy(name_str, readFromTarget->name, readFromTarget->len);
        name_str[readFromTarget->len] = '\0';
        name->name = name_str;
        name->len = readFromTarget->len;
        if (first && readFromTarget == finalDomainName)
            break;
        first = 0;
    }
    name->next = NULL;
    return head;
}

//将msg中的question加入全局变量taskList中
void putQuestionsInMsgToTaskList(struct Message* msg) {
    int count = 0;
    struct Question* q;
    struct Question* pq;
    q = msg->questions;
    while (q) {
        count++;
        pq = malloc(sizeof(struct Question));
        memset(pq, 0, sizeof(struct Question));
        pq->name = getBestMatchDomainName(q->name, NULL);
        pq->type = q->type;
        pq->class = q->class;
        pq->next = taskList;
        taskList = pq;

        q = q->next;
    }
}

//以UDP协议将packet发送出去
void sendQuery(struct Message* msg, unsigned char* remote_ip, struct DomainName* query_domain, int query_type) {
    struct timeval start, end;
    gettimeofday( &start, NULL );
    uint8_t buffer[BUF_SIZE];
    struct sockaddr_in dnsSvrAddr;
    struct sockaddr_in cltAddr;
    socklen_t addrLen = sizeof(struct sockaddr_in);
    unsigned short dnsSvrPort = 53;
    int sock;
    uint8_t* pointerForLength;
    int bufLen;

    memset(&dnsSvrAddr, 0, sizeof(dnsSvrAddr));/*Zero out structure*/
    dnsSvrAddr.sin_family = AF_INET;
    dnsSvrAddr.sin_addr.s_addr = inet_addr(remote_ip);
    dnsSvrAddr.sin_port = htons(dnsSvrPort);

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

    //讲道理此时作为一个客户端是不需要bind的，但是如果不bind，发出去的包的ip地址会是127.0.0.1，就看不出来这个包是哪个服务器发的了，
    //所以bind一下好看些
    struct sockaddr_in cltBindAddr;
    memset(&cltBindAddr,0,sizeof(cltBindAddr));
    cltBindAddr.sin_family = AF_INET;
    cltBindAddr.sin_addr.s_addr = inet_addr(myIpAddr);
    bind(sock, (struct sockaddr *) &cltBindAddr, sizeof(cltBindAddr));

    memset(msg, 0, sizeof(struct Message));
    memset(&buffer,0,sizeof(buffer));

    //准备header
    msg->id = rand()%BUF_SIZE;
    msg->qr = 0;//这是一条Query
    msg->aa = 0;
    if (isRecursive) {
        msg->rd = 1; //期望递归
        msg->ra = 1; //能够递归
    }
    else {
        msg->rd = 0;
        msg->ra = 0;
    }
    msg->rcode = 0;

    msg->qCount = 0;
    msg->ansCount = 0;
    msg->auCount = 0;
    msg->adCount = 0;

    struct Question* q;
    q = malloc(sizeof(struct Question));
    memset(q, 0, sizeof(struct Question));
    q->name = getBestMatchDomainName(query_domain, NULL);
    q->type = query_type;
    q->class = IN_Class;
    q->next = msg->questions;
    msg->questions = q;

    msg->qCount++;

    pointerForLength = buffer;
    writeBuffer(msg, &pointerForLength);
    bufLen = pointerForLength - buffer;

    if ((sendto(sock, buffer, bufLen, 0, (struct sockaddr *) &dnsSvrAddr, sizeof(dnsSvrAddr)))!= bufLen)
        printf("sendto() sent a different number of bytes than expected.\n");

    freeQuestions(msg->questions);
    freeResourceRecords(msg->answers);
    freeResourceRecords(msg->authorities);
    freeResourceRecords(msg->additionals);

    memset(msg, 0, sizeof(struct Message));
    memset(buffer, 0, sizeof(buffer));
    recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &cltAddr, &addrLen);
    readBuffer(msg, buffer);
    printf("\n\nResponse from %s:\n",remote_ip);
    printMessage(msg);
    gettimeofday(&end, NULL );
    int timeuse = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;
    printf("time: %d us\n", timeuse);
    close(sock);
}

//删掉当前任务，将下一个任务提到当前来
//因为这几行代码用的次数很多所以单独提出来当一个函数了
void moveTaskList2Next() {
    struct Question* next;
    next = taskList->next;
    freeDomainName(taskList->name);
    free(taskList);
    taskList = next;
}

//先在serverFile中查找最佳匹配的权威服务器，如果找到了，那么进入while循环，此时应该不断向已知IP请求解析，然后得到新的权威服务器IP，
//再向新IP请求解析，循环直到得到请求的域名的解析为止。
//注意每次请求的域名都是一模一样的，比如你请求的是北邮.教育.中国的MX，那么你问根、中国、教育的时候，question section里的内容永远都是北邮.教育.中国的MX。
//如果没找到但是服务器是local server，那么就从"根.网络"开始请求
//如果没找到服务器也不是local server，此题无解，删除跳过
void queryAsAClient(struct DomainName* query_domain, struct ResourceRecord* rr) {
    int rc, origType, hasResult;
    unsigned char* addr;
    unsigned char* ipStr;
    struct Message* msg;

    origType = rr->type;
    rr->type = A_Resource_RecordType;
    rc = getRecordFromFile(rr, query_domain, serverFile);//check serverFileName
    if (isLocal && rc <0) {
        query_domain = domainBytes2DomainStructureFromStr(domainStr2DomainBytes("根.网络"));
        rc = getRecordFromFile(rr, query_domain, serverFile);
    }
    rr->type = origType;
    if (rc > 0) {
        addr = rr->rd_data.a_record.addr;
        while (1) {
            ipStr = malloc(sizeof(unsigned char)*16);
            memset(ipStr,0,sizeof(unsigned char)*16);
            sprintf(ipStr,"%u.%u.%u.%u",addr[0],addr[1],addr[2],addr[3]);
            msg = malloc(sizeof(struct Message));
            memset(msg,0,sizeof(struct Message));
            sendQuery(msg, ipStr, taskList->name, rr->type);
            hasResult = 0;
            hasResult+= saveRecord2File(msg->answers, taskList->name, cacheFile, rr->type, 0);
            hasResult+= saveRecord2File(msg->additionals, taskList->name, cacheFile, rr->type, 1);
            //saveRecord2File(msg->authorities, taskList->qName, serverFileName, rr->type, 1); //权威服务器不可缓存
            //save_record_to_file的if里有判定条件，只有rr与所请求的完全匹配的情况下才存入文件，除非force save是1
            if (hasResult>0)
                break;
                //saveRecord2File函数的返回结果是这些section中是否包含原始请求的解析结果，如果包含解析结果，那么直接break此函数，
                //程序会回到main函数中的taskList那个循环，从头开始重新解析，也就是重新从文件中找解析结果，此时因为结果已经存入文件，
                //所以可以成功解析，解析过程结束。
            else {
                if(msg->auCount>0) {
                    if(msg->authorities->type == A_Resource_RecordType) {
                        addr = msg->authorities->rd_data.a_record.addr;
                        continue;
                    }
                    else {
                        //原则上讲authority section的内容应该是一个NS，然后在additional section存着这个NS的A解析，不过作业要求里没有NS解析
                    }
                }
                moveTaskList2Next();
                msg->rcode = Refused_ResponseType;//没有authority section，解析失败，修改return code，这热Refused是瞎设的因为我也不知道该设啥
                return;
            }
        }
    }
    else {
        moveTaskList2Next();//没有在serverFile内找到最佳匹配的权威服务器，此题无解，删除跳过。
        return;
    }
}

//解析过程函数
//逻辑是先从resolveFile文件和cacheFile文件中查找完全匹配，如果找到了，将此任务移出taskList，将rr放入answer section，
//如果请求类型是MX那还得再找一遍它的A解析加入additional section
//如果没找到完全匹配，那么从serverFile中查找最佳匹配，也就是调用一遍自己checkNameServer设为1，
//如果找到了，将此任务移出taskList，将rr放入authority section
//如果没找到，就不管了，直接从taskList移除。
void resolveTask(struct Message* msg, int checkNameServer) {
    int rc;
    struct ResourceRecord* rr;
    rr = malloc(sizeof(struct ResourceRecord));
    memset(rr, 0, sizeof(struct ResourceRecord));
    rr->name = getBestMatchDomainName(taskList->name, NULL);
    rr->type = taskList->type;
    rr->class = taskList->class;
    switch (rr->type)
    {
        case A_Resource_RecordType:
        case CNAME_Resource_RecordType:
        case MX_Resource_RecordType:
            if(!checkNameServer) {
                
                rc = getRecordFromFile(rr, rr->name, resolveFile);
                if (rc != 2) {
                    free(rr->name);
                    free(rr);
                    rr = malloc(sizeof(struct ResourceRecord));
                    memset(rr, 0, sizeof(struct ResourceRecord));
                    rr->name = getBestMatchDomainName(taskList->name, NULL);
                    rr->type = taskList->type;
                    rr->class = taskList->class;
                    rc = getRecordFromFile(rr, rr->name, cacheFile);
                }
            }
            else
                rc = getRecordFromFile(rr, rr->name, serverFile);
            break;

        default:
            msg->rcode = NotImplemented_ResponseType;
            printf("Cannot answer question of type %d.\n", rr->type);
            rc=-1;
    }

    if( !checkNameServer ) {
        if ( rc==2 ) {
            struct Question* next;
            next = taskList->next;
            freeDomainName(taskList->name);
            free(taskList);
            taskList = next;

            msg->ansCount++;
            rr->next = msg->answers;
            msg->answers = rr;

            if (rr->type == MX_Resource_RecordType) {
                struct ResourceRecord* rr_mx;
                rr_mx = malloc(sizeof(struct ResourceRecord));
                memset(rr_mx, 0, sizeof(struct ResourceRecord));
                rr_mx->name = getBestMatchDomainName(domainBytes2DomainStructureFromStr(rr->rd_data.mx_record.exchange), NULL);
                rr_mx->type = A_Resource_RecordType;
                rr_mx->class = rr->class;
                rc = getRecordFromFile(rr_mx, rr_mx->name, resolveFile);
                if (rc != 2) {
                    free(rr_mx->name);
                    free(rr_mx);
                    rr_mx = malloc(sizeof(struct ResourceRecord));
                    memset(rr_mx, 0, sizeof(struct ResourceRecord));
                    rr_mx->name = getBestMatchDomainName(domainBytes2DomainStructureFromStr(rr->rd_data.mx_record.exchange), NULL);
                    rr_mx->type = A_Resource_RecordType;
                    rr_mx->class = rr->class;
                    rc = getRecordFromFile(rr_mx, rr_mx->name, cacheFile);
                }
                if ( rc > 0 ) {
                    msg->adCount++;
                    rr_mx->next = msg->additionals;
                    msg->additionals = rr_mx;
                } else {
                    free(rr_mx->name);
                    free(rr_mx);
                }
            }
        }
        else {
            taskList->type = A_Resource_RecordType;
            resolveTask(msg, 1);
        }
    } else {
        if ( rc<0 ) {
            free(rr->name);
            free(rr);
            struct Question* next;
            next = taskList->next;
            freeDomainName(taskList->name);
            free(taskList);
            taskList = next;
        } else {
            struct Question* next;
            next = taskList->next;
            freeDomainName(taskList->name);
            free(taskList);
            taskList = next;
            msg->auCount++;
            rr->next = msg->authorities;
            msg->authorities = rr;
        }
    }
}

//local server的解析函数过程
//逻辑是先从resolveFile和cacheFile中找完全匹配，找到了就直接按照普通的resolveTask函数跑，所以直接调用了resolveTask函数
//没找到就像客户端一样去向根服务器开始请求解析
//注意getBestMatchDomainName函数在第二个参数是NULL时效果就是复制一遍这个链表
void resolveTaskForLocalServer(struct Message* msg) {
    int rc;
    struct ResourceRecord* rr;
    rr = malloc(sizeof(struct ResourceRecord));
    memset(rr, 0, sizeof(struct ResourceRecord));
    rr->name = getBestMatchDomainName(taskList->name, NULL);
    rr->type = taskList->type;
    rr->class = taskList->class;

    switch (rr->type) {
        case A_Resource_RecordType:
        case CNAME_Resource_RecordType:
        case MX_Resource_RecordType:
            rc = getRecordFromFile(rr, rr->name, resolveFile);
            if (rc!=2) {
                free(rr->name);
                free(rr);
                rr = malloc(sizeof(struct ResourceRecord));
                memset(rr, 0, sizeof(struct ResourceRecord));
                rr->name = getBestMatchDomainName(taskList->name, NULL);
                rr->type = taskList->type;
                rr->class = taskList->class;
                rc = getRecordFromFile(rr, rr->name, cacheFile);
            }
            break;

        default:
            free(rr->name);
            free(rr);
            msg->rcode = NotImplemented_ResponseType;
            printf("无法解析类型：%d\n", rr->type);
            struct Question* next;
            next = taskList->next;
            freeDomainName(taskList->name);
            free(taskList);
            taskList = next;
            return;
    }

    if (rc==2) {
        resolveTask(msg, 0);
    }
    else {
        queryAsAClient(getBestMatchDomainName(taskList->name, NULL), rr);
        free(rr->name);
        free(rr);
    }
}

void writeMsgHeader(struct Message* msg) {
    //写入回复Message的header
    msg->qr = 1; //这是一条Response
    if (!isLocal)
        msg->aa = 1; //此服务器权威
    else
        msg->aa = 0;
    if (isRecursive) {
        msg->rd = 1; //期望递归
        msg->ra = 1; //能够递归
    }
    else {
        msg->rd = 0;
        msg->ra = 0;
    }
    msg->rcode = Ok_ResponseType;
    msg->ansCount = 0;
    msg->auCount = 0;
    msg->adCount = 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("使用说明: %s <绑定IP> <文件前缀> <服务器类型>\n", argv[0]);
        printf("其中，如文件前缀为“某文件”，则程序会以工作目录下的“某文件resolve.txt”为解析数据库，\n");
        printf("“某文件authorised.txt”为权威服务器数据库，“某文件cache.txt”为缓存数据库，请确保三个文件全部存在。\n");
        printf("服务器类型：0为local服务器，1为普通服务器，2为支持递归的普通服务器");
        exit(1);
    }

    struct timeval boot, start, end;
    struct sockaddr_in CltAddr;
    socklen_t AddrLen = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    int sock,sockTcp,sockTcp2;
    int port = 53;
    int rc, rcTcp, rcListen, timeuse;
    struct Message msg;
    unsigned char* resolveFileTemp;
    unsigned char* serverFileTemp;
    unsigned char* cacheFileTemp;

    uint8_t buffer[BUF_SIZE];//用于存储字节码packet的buffer
    int bufLen;
    uint8_t* pointerForRead;
    uint8_t* pointerForWrite;
    uint8_t* pointerForLength;

    resolveFileTemp = malloc(sizeof(unsigned char)*BUF_SIZE);
    memset(resolveFileTemp,0,sizeof(unsigned char)*BUF_SIZE);
    serverFileTemp = malloc(sizeof(unsigned char)*BUF_SIZE);
    memset(serverFileTemp,0,sizeof(unsigned char)*BUF_SIZE);
    cacheFileTemp = malloc(sizeof(unsigned char)*BUF_SIZE);
    memset(cacheFileTemp,0,sizeof(unsigned char)*BUF_SIZE);
    memcpy(resolveFileTemp,argv[2],strlen(argv[2])+1);
    memcpy(serverFileTemp,argv[2],strlen(argv[2])+1);
    memcpy(cacheFileTemp,argv[2],strlen(argv[2])+1);

    myIpAddr = argv[1];
    resolveFile = strcat(resolveFileTemp,"resolve.txt");
    serverFile = strcat(serverFileTemp,"authorised.txt");
    cacheFile = strcat(cacheFileTemp,"cache.txt");
    switch(atoi(argv[3])) {
        case 0:
            isLocal = 1;
            isRecursive = 1;
            break;

        case 1:
            isLocal = 0;
            isRecursive = 0;
            break;

        case 2:
            isLocal = 0;
            isRecursive = 1;
            break;

        default:
            isLocal = 0;
            isRecursive = 0;
            break;
    }

    gettimeofday( &boot, NULL );
    srand(1000000*boot.tv_sec+boot.tv_usec);//用当前时间精确到微秒的数据生成随机数种子

    memset(&msg, 0, sizeof(struct Message));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(myIpAddr);
    addr.sin_port = htons(port);

    if (isLocal) {
        sockTcp = socket(PF_INET, SOCK_STREAM, 0);
        rcTcp = bind(sockTcp, (struct sockaddr *) &addr, sizeof(addr));
        rcListen = listen(sockTcp, 100);
        if (rcTcp != 0 || rcListen < 0) {
            printf("TCP端口绑定失败！\n");
            return 1;
        }
    }
    else {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        rc = bind(sock, (struct sockaddr*) &addr, AddrLen);
        if (rc != 0) {
            printf("UDP端口绑定失败！\n");
            return 1;
        }
    }

    printf("正在监听%s:%u\n", myIpAddr, port);

    while (1) {
        //清空释放所有链表
        freeQuestions(msg.questions);
        freeResourceRecords(msg.answers);
        freeResourceRecords(msg.authorities);
        freeResourceRecords(msg.additionals);

        memset(&msg, 0, sizeof(struct Message));
        memset(&buffer, 0, sizeof(buffer));

        if (isLocal) {
            sockTcp2=accept(sockTcp, (struct sockaddr *) &CltAddr, &AddrLen);
            recv(sockTcp2, buffer, sizeof(buffer), 0);
            pointerForRead = buffer;
            get16bits(&pointerForRead);//跳过TCP包的前两个用于记录包总长度的字节
        }
        else {
            recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &CltAddr, &AddrLen);
            pointerForRead = buffer;
        }

        gettimeofday( &start, NULL );//记录开始查询的时间
        readBuffer(&msg, pointerForRead);
        printMessage(&msg);

        writeMsgHeader(&msg);

        //开始解析
        putQuestionsInMsgToTaskList(&msg);
        while (taskList) {
            if (isLocal || isRecursive) {
                resolveTaskForLocalServer(&msg);
            }
            else {
                resolveTask(&msg, 0);
            }
        }

        printMessage(&msg);//打印准备好的回复

        //开始将msg写入buffer
        memset(&buffer,0,sizeof(buffer));

        pointerForWrite = buffer;
        if (isLocal) {
            //TCP，先写入两个字节占位，等消息都写完了再回到这里来补填长度
            put16bits(&pointerForWrite, 0);
        }
        writeBuffer(&msg, &pointerForWrite);
        bufLen = pointerForWrite - buffer;
        if (isLocal){
            pointerForLength = buffer;
            put16bits(&pointerForLength, bufLen-2);//回到buffer的最开始，写入2个字节的长度信息，其中减2是因为长度不包括记录长度的那两个字节自己
            send(sockTcp2, buffer, bufLen, 0);
            close(sockTcp2);
        }else {
            sendto(sock, buffer, bufLen, 0, (struct sockaddr*) &CltAddr, AddrLen);
        }

        gettimeofday(&end, NULL); //记录结束时间
        timeuse = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;//计算时间差
        printf("time: %d us\n", timeuse);
    }
}
