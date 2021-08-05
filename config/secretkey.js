
// CMD npm i mymodule --save

module.exports = {

    secretKey : '437908feji#$7843jfeji3', //salt값
    options : {
        algorithm : "HS256",   // hash 알고리즘
        expiresIn : "10h",     // 발행된 토큰의 유효시간(10h)    
        issuer    : "corp01"   // 발행자
    }

}
