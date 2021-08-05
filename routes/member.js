// 벡엔드 routes/member.js
var express = require('express');
var router = express.Router();

const crypto = require('crypto');
const secretkey = '348!_2376y_fe3re9i8439'; // salt 값


// 회원가입시 hash
const crypta = require('crypto');
//로그인시 token발행
const randToken = require('rand-token');
const jwt = require('jsonwebtoken');
const secretKey = require('../config/secretkey').secretKey;
const options = require('../config/secretkey').options;

const checkToken = require('../config/auth').checkToken;


// mongodb연동 설정
const mongoclient = require('mongodb').MongoClient;
const ObjectId    = require('mongodb').ObjectId;
// 아이디:암호@서버주소:포트번호/DB명
const mongourl    = "mongodb://id315:pw315@1.234.5.158:37017/id315";


// 회원가입 ( 이메일, 암호, 이름, 연락처, 등록일자(X) )
// http://127.0.0.1:3000/member/join
// 유효성검사완료 후 전송되는 것으로 가정

// [POST] http://127.0.0.1:3000/member/join
router.post('/join', async function(req, res, next) {
    try {
        // 1. 전달되는 값 받기(body.name값일치)
        const hash = crypto.createHmac('sha256', req.body.email)
                        .update(req.body.password).digest('hex');
        const obj = {
            _id         : req.body.email,
            password    : hash,
            name        : req.body.name,
            phone       : req.body.phone,
            regdate     : new Date()
        }
        console.log(obj); // debug용

        // 2. db연결 하기
        const dbconn     = await mongoclient.connect(mongourl);
        const collection = dbconn.db("id315").collection("member7");

        // 3. db에 추가하기
        const result = await collection.insertOne(obj);
        console.log(result);

        // 4. db닫기
        dbconn.close();

        // 5. 결과리턴
        if(result.insertedId === obj._id){
            res.send({ret:1, data:'회원가입 성공'});
        }
        else{
            res.send({ret:0, data:'회원가입 실패'});
        }
    }
    catch(error) {
        console.error(error);
        res.send({ret:-1, data:error});
    }
});

// 로그인 (이메일, 암호)
// [POST] http://127.0.0.1:3000/member/login
router.post('/login', async function(req, res, next) {
    try {
        // 1. 전달값 받기
        const email = req.body.email;  //key : email
        const password = req.body.password;  //key:password
        console.log(email, password);

        // 2. 회원가입방식과 암호는 hash후 비교
        const hash = crypto.createHmac('sha256', email)
            .update(password).digest('hex');
        console.log(hash);

        // 3. db연결
        const dbconn     = await mongoclient.connect(mongourl);
        const collection = dbconn.db("id315").collection("member7");
        
        // 4. db에서 조회
        const query  = {_id:email, password:hash};
        const result = await collection.findOne(query);
        console.log(result);

        // 5. result의 결과에 따라서 token 생성
        if(typeof(result)  !== 'undefined') {
            const payload = { //token에 저장되는 내용
                idx     : result._id,
                name    : result.name
            };
            
            console.log(secretKey, options);
            const resultToken = {
                token : jwt.sign(payload, secretKey, options),
                refreshToken : randToken.uid(256)
            }
            // DB에 생성한 token을 update
            const query1  = { _id : email }
            const changeData = { $set : {token : resultToken} };

            const result1 = await collection.updateOne(query1, changeData);
            if(result1.modifiedCount === 1){
                res.send( {ret:1, jwtToken : resultToken} );
            }
            else {
                res.send( {ret:0, data:'token 발행 실패'} );
            }
        }
        else { // 이메일, 암호가 일치하지 않으면
            res.send( {ret : 0, data:'token 발행 실패'} );
        }
    }
    catch(error){
        console.error(error);
        res.send( {ret : -1, data : error} );
    }
});


// 회원정보수정 (이름 ,연락처)
// [PUT] http://127.0.0.1:3000/member/update
router.put('/update', checkToken, async function(req,res,next){
    try{
        //0.인증 통과후 전달된 값 받기
        //token을 decode했을때 정보가 있기 때문에
        const email = req.idx;
        const name =req.body.name;
        const phone = req.body.phone;

        //1.DB연결
        const dbconn     = await mongoclient.connect(mongourl);
        const collection = dbconn.db("id315").collection("member7");

        //2. DB저장
        const query = {_id:email};
        const changeData = {$set : {name : name, phone : phone } };
        const result1 = await collection.updateOne(query, changeData);
        if(result1.modifiedCount === 1){
            return res.send( {ret:1, data:'정보 수정 완료'} );
        }
        res.send( {ret:0, data:'정보 수정 실패'} );
        }
        catch(error){
        console.error(error);
        res.send({ret:-1, data:error});
        }
        });

        // 이메일 중복확인(이메일)
// [GET] http://127.0.0.1:3000/member/emailcheck
router.get('/emailcheck', async function(req, res, next) {
    try {
        // 0. 전달값 받기
        const email = req.query.email;

        // 1. DB 연결
        const dbconn     = await mongoclient.connect(mongourl);
        const collection = dbconn.db("id315").collection("member7");

        // 2. DB에서 이메일을 조건으로 하여 개수 조회 countDocuments
        const query = {_id : email};
        const result = await collection.countDocuments(query);

        // 3. 개수리턴 {ret:1 data:개수}
        res.send({ret:1, data:result});
    }
    catch(error) {
        console.error(error);
        res.send({ret:-1, data:error});
    }
});


// 비밀번호 변경 (변경할 암호)
//[POST] http://127.0.0.1:3000/member/changepw
router.put('/changepw',checkToken,async function(req,res,next){
    try{
        //0.값받기
        //checkToken에서 성공 req.idx <= 이메일
        //body.newpassword
        const email = req.idx;
        const newpassword = req.body.newpassword;
        //1.DB연결
        const dbconn     = await mongoclient.connect(mongourl);
        const collection = dbconn.db("id315").collection("member7");
        //2. newpassword hash 하기
        const hash = crypto.createHmac('sha256', email)
        .update(newpassword).digest('hex');
        console.log(hash);
        //3. DB에 저장
        const query = {_id:email};
        const changeData = {$set : {password:hash} };
        const result = await collection.updateOne(query, changeData);
        console.log(result);
        console.log("result");
        //4. DB 닫기
        dbconn.close();
        //5.결과 반환
        if(result.modifiedCount === 1){
            return res.send({data:"암호 변경 성공" ,ret:1});
        }
        else{
            return res.send({data:"암호 변경 실패", ret:-0});
        }
       
    }
    catch(error) {
        console.error(error);
        res.send({ret:-1, data:error});
    }
});

module.exports = router;
