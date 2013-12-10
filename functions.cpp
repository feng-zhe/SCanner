#include <QString>
bool ipQStrToUint(const QString ipStr,uint &ip)
{
    uint sum = 0,temp = 0;
    for(int i=0;i<4;++i){
        temp = ipStr.section(".",3-i,3-i).trimmed().toUInt();
        if( temp>255 )
            return false;
        else
            sum = sum*256+temp;
    }
    ip = sum;
    return true;
}
