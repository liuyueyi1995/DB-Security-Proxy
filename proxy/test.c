#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <mysql/mysql.h>
#include <sys/types.h>
#include "aes_api.h"
#include <uuid/uuid.h>

char* shellcmd(char* cmd, char* buff, int size);

int main(int argc, char**argv) {
  if (argc < 3) { //输入参数的判断及用法提示
    printf("usage1: ./sql insert id name age\n");
    printf("usage2: ./sql delete cond value\n");
    printf("usage3: ./sql select cond value\n");
    printf("usage4: ./sql update key value cond value\n\n");
    exit(1);
  }

  const char* type = argv[1]; //获取要执行的操作
  unsigned char rootkey[AES_BLOCK_SIZE+1] = "liuyueyipassword\0"; //根密钥
  unsigned char iv[AES_BLOCK_SIZE+1] = "liuyueyipassword\0";  //初始向量
  char qbuf[102400]={0};      //存放sql语句字符串
  char *end; //用于拼接qbuf的指针
  MYSQL conn;  //数据库连接句柄

  mysql_init(&conn);

  if (!mysql_real_connect(&conn,"127.0.0.1","root","passpass","liuyueyi_test",0,NULL,0)) {
    fprintf(stderr, "Connection failed!\n");
    if (mysql_errno(&conn)) {
      fprintf(stderr, "Connection error %d: %s\n", mysql_errno(&conn), mysql_error(&conn));
    }
    exit(1);
  }

  //根据type的不同选择分支
  if(strcmp(type,"insert") == 0) {
    unsigned char *result1;
    unsigned char *result2;
    unsigned char *result3;
    int len_sql;  //SQL请求长度
    int res;  //数据库操作返回码
    int id, age;
    char buff[1024]; //存储shell命令输出的结果
    char buff2[1024]; //存储shell命令输出的结果
    char* shell_return;
    char cmd[1024];
    char cmd2[1024];
    FILE *fp;   //保存同态加密结果的文件
    unsigned char filebuffer[40000]; //同态加密的结果
    unsigned char filebuffer2[40000]; //同态加密的结果
    int file_length;
    int file_length2;

    memset(buff, 0, sizeof(buff));
    memset(cmd, 0, sizeof(cmd));
    memset(filebuffer, 0, sizeof(filebuffer));
    memset(buff2, 0, sizeof(buff2));
    memset(cmd2, 0, sizeof(cmd2));
    memset(filebuffer2, 0, sizeof(filebuffer2));

    result1 = RND_ENC(argv[2],rootkey,iv);
    result2 = RND_ENC(argv[3],rootkey,iv);
    result3 = RND_ENC(argv[4],rootkey,iv);
    id = atoi(argv[2]);
    age = atoi(argv[4]);

    //对id列进行同态加密
    sprintf(cmd,"./seal enc %d",id); //拼接shell command
    printf("%s\n",cmd);
    shell_return = shellcmd(cmd, buff, sizeof(buff)); //调用shell command执行SEAL模块
    printf("%s\n",shell_return);

    if (strcmp(shell_return,"ERROR") != 0) {  //说明同态加密已经成功
      //将文件中的内容读入,此时shell_return就是结果所在文件的文件名
      fp = fopen(shell_return, "rb");
      if(fp==NULL) {
        return;
      }

      fseek(fp,0,SEEK_END);
      file_length = ftell(fp); //求文件大小
      rewind(fp); //把指针移动到文件开头 因为我们一开始把指针移动到结尾，如果不移动回来 会出错
      fread(filebuffer,1,file_length,fp); //读文件
      fclose(fp);

    } else {
      printf("shell command run error!\n");
      return -1;
    }

    //对age列进行同态加密
    sprintf(cmd2,"./seal enc %d",age); //拼接shell command
    printf("%s\n",cmd2);
    shell_return = shellcmd(cmd2, buff2, sizeof(buff2)); //调用shell command执行SEAL模块
    printf("%s\n",shell_return);

    if (strcmp(shell_return,"ERROR") != 0) {  //说明同态加密已经成功
      //将文件en中的内容读入
      fp = fopen(shell_return, "rb");
      if(fp==NULL) {
        return;
      }

      fseek(fp,0,SEEK_END);
      file_length2 = ftell(fp); //求文件大小
      rewind(fp); //把指针移动到文件开头 因为我们一开始把指针移动到结尾，如果不移动回来 会出错
      fread(filebuffer2,1,file_length2,fp); //读文件
      fclose(fp);

    } else {
      printf("shell command run error!\n");
      return -1;
    }

    //拼接SQL
    sprintf(qbuf,"INSERT INTO users_enc_test(id_EQ,id_HOM,name_EQ,age_EQ,age_HOM) VALUES(");
    end = qbuf + strlen(qbuf);
    *end++ = '\'';
    end += mysql_real_escape_string(&conn,end,(unsigned char*)result1,strlen(result1)*sizeof(unsigned char));
    *end++ = '\'';
    *end++ = ',';
    *end++ = '\'';
    end += mysql_real_escape_string(&conn,end,(unsigned char*)filebuffer,file_length*sizeof(unsigned char));
    *end++ = '\'';
    *end++ = ',';
    *end++ = '\'';
    end += mysql_real_escape_string(&conn,end,(unsigned char*)result2,strlen(result2)*sizeof(unsigned char));
    *end++ = '\'';
    *end++ = ',';
    *end++ = '\'';
    end += mysql_real_escape_string(&conn,end,(unsigned char*)result3,strlen(result3)*sizeof(unsigned char));
    *end++ = '\'';
    *end++ = ',';
    *end++ = '\'';
    end += mysql_real_escape_string(&conn,end,(unsigned char*)filebuffer2,file_length2*sizeof(unsigned char));
    *end++ = '\'';
    *end++ = ')';

    printf("-----\nSQL:\n%s\n-----\n",qbuf);
    len_sql = strlen(qbuf);
    res = mysql_real_query(&conn,qbuf,len_sql); //发送SQL

    //结果处理
    if (!res) {
      printf("Succeed!\n");
    } else {
      printf("Query failed. %d: %s\n", mysql_errno(&conn), mysql_error(&conn));
    }

  } else if(strcmp(type,"delete") == 0) {
    unsigned char *result1;
    unsigned char *result2;
    int len_sql;  //SQL请求长度
    int res;  //数据库操作返回码

    result2 = RND_ENC(argv[3],rootkey,iv); //先赋值result2，防止之后strcat覆盖掉argv[3]
    result1 = strcat(argv[2],"_EQ");

    //拼接SQL
    sprintf(qbuf,"DELETE FROM users_enc_test WHERE %s = ",result1);
    end = qbuf + strlen(qbuf);
    *end++ = '\'';
    end += mysql_real_escape_string(&conn,end,(unsigned char*)result2,strlen(result2)*sizeof(unsigned char));
    *end++ = '\'';

    printf("-----\nSQL:\n%s\n-----\n",qbuf);
    len_sql = strlen(qbuf);
    res = mysql_real_query(&conn,qbuf,len_sql); //发送SQL

    //结果处理
    if (!res) {
      printf("Succeed!\n");
    } else {
      printf("Query failed. %d: %s\n", mysql_errno(&conn), mysql_error(&conn));
    }

  } else if(strcmp(type,"select") == 0) {
    unsigned char *result1;
    unsigned char *result2;
    int len_sql;
    MYSQL_RES *res;       //查询结果集，结构类型
    MYSQL_FIELD *fd ;     //包含字段信息的结构
    MYSQL_ROW row ;       //存放一行查询结果的字符串数组

    result2 = RND_ENC(argv[3],rootkey,iv); //先赋值result2，防止之后strcat覆盖掉argv[3]
    result1 = strcat(argv[2],"_EQ");

    //拼接SQL
    sprintf(qbuf,"SELECT id_EQ, name_EQ, age_EQ FROM users_enc_test WHERE %s = ",result1);
    end = qbuf + strlen(qbuf);
    *end++ = '\'';
    end += mysql_real_escape_string(&conn,end,(unsigned char*)result2,strlen(result2)*sizeof(unsigned char));
    *end++ = '\'';

    printf("-----\nSQL:\n%s\n-----\n",qbuf);
    len_sql = strlen(qbuf);

    if(mysql_real_query(&conn,qbuf,len_sql)) {//发送SQL
      fprintf(stderr,"Query failed (%s)\n",mysql_error(&conn));
      exit(1);
    }

    //结果处理
    if (!(res=mysql_store_result(&conn))) {
      fprintf(stderr,"Couldn't get result from %s\n", mysql_error(&conn));
      exit(1);
    }

    printf("number of fields returned: %d\n",mysql_num_fields(res));
    printf("The results are:\nid\tname\tage\t\n");

    //解密返回的结果集
    while (row = mysql_fetch_row(res)) {
      unsigned char *result1 = row[0];
      unsigned char *result2 = row[1];
      unsigned char *result3 = row[2];

      result1 = RND_DEC(result1,rootkey,iv);
      result2 = RND_DEC(result2,rootkey,iv);
      result3 = RND_DEC(result3,rootkey,iv);
      printf("%s\t%s\t%s\t\n",result1,result2,result3);
      /*(((row[0]==NULL)&&(!strlen(row[0]))) ? "NULL" : row[0]),
      (((row[1]==NULL)&&(!strlen(row[1]))) ? "NULL" : row[1]),
      (((row[2]==NULL)&&(!strlen(row[2]))) ? "NULL" : row[2])); */
    }

  } else if(strcmp(type,"update") == 0) {
    unsigned char *result1;
    unsigned char *result2;
    unsigned char *result3;
    unsigned char *result4;
    int len_sql;  //SQL请求长度
    int res;  //数据库操作返回码

    result4 = RND_ENC(argv[5],rootkey,iv); //先赋值result4，防止之后strcat覆盖掉argv[5]
    result2 = RND_ENC(argv[3],rootkey,iv); //先赋值result2，防止之后strcat覆盖掉argv[3]
    result3 = strcat(argv[4],"_EQ");
    result1 = strcat(argv[2],"_EQ");

    //拼接SQL
    sprintf(qbuf,"UPDATE users_enc_test SET %s = ",result1);
    end = qbuf + strlen(qbuf);
    *end++ = '\'';
    end += mysql_real_escape_string(&conn,end,(unsigned char*)result2,strlen(result2)*sizeof(unsigned char));
    *end++ = '\'';
    end += mysql_real_escape_string(&conn,end," WHERE ",7*sizeof(char));
    end += mysql_real_escape_string(&conn,end,(unsigned char*)result3,strlen(result3)*sizeof(unsigned char));
    *end++ = '=';
    *end++ = '\'';
    end += mysql_real_escape_string(&conn,end,(unsigned char*)result4,strlen(result4)*sizeof(unsigned char));
    *end++ = '\'';

    printf("-----\nSQL:\n%s\n-----\n",qbuf);
    len_sql = strlen(qbuf);
    res = mysql_real_query(&conn,qbuf,len_sql); //发送SQL

    //结果处理
    if (!res) {
      printf("Succeed!\n");
    } else {
      printf("Query failed.%d: %s\n", mysql_errno(&conn), mysql_error(&conn));
    }

  } else if(strcmp(type,"sum") == 0) {
    /**
     * 求和操作，./test sum age，即可得到age列所有值的总和
     * SELECT SUM(age) FROM users_enc_test;
     * 被改写成 SELECT age_HOM FROM users_enc_test;
     * 得到所有的HOM值之后，在代理端调用SEAL模块完成同态运算并解密返回明文结果
     */
    unsigned char *result1;
    unsigned char *return_result;
    int len_sql;  //SQL请求长度
    MYSQL_RES *res;       //查询结果集，结构类型
    MYSQL_FIELD *fd ;     //包含字段信息的结构
    MYSQL_ROW row ;       //存放一行查询结果的字符串数组
    char buff[1024];
    char* shell_return_add;
    char* shell_return_dec;
    char cmd_add[102400] = {0};
    char cmd_dec[60] = {0};
    char filename[37];
    char* final_result;
    FILE* fp;
    int file_length;

    result1 = strcat(argv[2],"_HOM");

    sprintf(qbuf,"SELECT %s FROM users_enc_test",result1);
    printf("-----\nSQL:\n%s\n-----\n",qbuf);
    len_sql = strlen(qbuf);
    if(mysql_real_query(&conn,qbuf,len_sql)) {//发送SQL
      fprintf(stderr,"Query failed (%s)\n",mysql_error(&conn));
      exit(1);
    }
    //结果处理
    if (!(res=mysql_store_result(&conn))) {
      fprintf(stderr,"Couldn't get result from %s\n", mysql_error(&conn));
      exit(1);
    }
    strcpy(cmd_add,"./seal add"); //拼接cmd_add
    //对结果进行同态运算
    while (row = mysql_fetch_row(res)) {
      /**
       * 获取数据之后，写进文件，
       * 调用SEAL模块去完成加法运算./seal add filename1 filename2
       * 运算结果写进文件，调用./seal dec filename去解密
       */
      return_result = row[0]; //原始的blob数据
      //生成随机文件名
      uuid_t uu;
      uuid_generate(uu);
      uuid_unparse(uu,filename);
      //将blob写入文件
      fp = fopen(filename,"wb");
      fwrite(return_result,1,32796,fp); //32796是序列化之后文件的大小
      fclose(fp);

      //拼接cmd_add
      strcat(cmd_add," ");
      strcat(cmd_add,filename);
    }
    //printf("cmd_add:\n%s\n",cmd_add);
    shell_return_add = shellcmd(cmd_add, buff, sizeof(buff)); //调用shell command执行SEAL模块
    //printf("add_result file:\n%s\n",shell_return_add);  //得到运算结果的文件名

    if (strcmp(shell_return_add,"ERROR") != 0) {  //说明同态运算已经成功
      sprintf(cmd_dec,"./seal dec %s",shell_return_add);//拼接cmd_dec
      shell_return_dec = shellcmd(cmd_dec, buff, sizeof(buff));//调用./seal dec filename解密结果
      if (strcmp(shell_return_dec,"ERROR") != 0) {  //说明同态解密已经成功
        printf("final_result:\n%s\n",shell_return_dec);
      }
    } else {
      printf("shell command run error!\n");
      return -1;
    }
  } else {
    printf("Type只能是insert、delete、select、update。\n");
  }

  mysql_close(&conn); //关闭连接
  return 0;
}

char* shellcmd(char* cmd, char* buff, int size) { //调用shell执行SEAL同态加密的模块
  char temp[256];
  FILE* fp = NULL;
  int offset = 0;
  int len;

  fp = popen(cmd, "r"); //管道模式执行shell命令
  if(fp == NULL) {
    return NULL;
  }

  while(fgets(temp, sizeof(temp), fp) != NULL) {
    len = strlen(temp);
    if(offset + len < size) {
      strcpy(buff+offset, temp);
      offset += len;
    } else {
      buff[offset] = 0;
      break;
    }
  }

  if(fp != NULL) {
    pclose(fp);
  }

  return buff;
}
