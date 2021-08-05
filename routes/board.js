var express = require('express');
var router = express.Router();

//GET: getting data => 조회해서 전달
//POST: creating data => 내용 추가
// PUT : updating data => 내용 변경
// DELETE :deleting data => 내용삭제

// mongodb연동 설정
const mongoclient = require('mongodb').MongoClient;
const ObjectId    = require('mongodb').ObjectId;

// 아이디:암호@서버주소:포트번호/DB명
const mongourl    = "mongodb://id315:pw315@1.234.5.158:37017/id315";

// 파일첨부 설정 
const multer      = require('multer');
const upload      = multer({storage : multer.memoryStorage()});

//글번호(자동증가를 위해서)

//mongodb에 counter7 컬렉션 만들기 입력완료 후 ctrl + enter
//db.counter7.insert({
//    _id:'SEQ_BOARD7_NO',
//    seq : 1
//});

//조회수 1증가

// http://127.0.0.1:3000/board/hit?_id=7
router.put('/hit', async function(req, res, next) {
    try{
        // 0.전달값 받기
        const _id = Number(req.query._id);

        // 1. db연결
        const dbconn = await mongoclient.connect(mongourl);
        var collection = dbconn.db("id315").collection("board7");

        // 2. db삭제
        const query = {_id : _id};
        const changeData = {$inc : {hit:1}};
        const result = await collection.updateOne(query,changeData);
        console.log(result);

        //결과값 리턴
        res.send({ret:1,data:'조회수 1증가 완료'});
    }


  catch(error){
        console.error(error);
        res.send({ret:-1,data:error});
    }
});
// application/json; charset=utf-8
//검색키워드에 따른 전체 게시물수
// http://127.0.0.1:3000/board/count?text=
router.get('/count', async function(req, res, next) {
    try {
        //1. 전달값.
        const text = req.query.text;
        

        //2. DB연동
        const dbconn     = await mongoclient.connect(mongourl);
        const collection = dbconn.db("id315").collection("board7");

        //3. 검색
        const query = { title : new RegExp(text, 'i') };
        const result = await collection.countDocuments(query);
        // console.log(result);

        //4. 결과 반환
        res.send({ret:1, data:result});
    }
    catch(error){
        console.error(error);
        res.send( {ret:-1, data:error} );
    }
});

// 이미지(크롬에서 확인)
// http://127.0.0.1:3000/board/image?_id=7
router.get('/image', async function(req, res, next) {
    try {
        // 1. 값받기
        const _id = Number(req.query._id);

        // 2. db연결
        const dbconn   = await mongoclient.connect(mongourl);
        const collection = dbconn.db("id315").collection("board7");

        // 3. 1개 조회
        const query = {_id : _id};
        const result = await collection.findOne(query, 
            { projection: {filedata : 1, filetype : 1} });
        
        console.log(result); // 데이터 구조 확인
        // 4. 이미지로 전달(json 으로 전달 X)
        res.contentType(result.filetype);
        res.send(result.filedata.buffer);
        res.end();
    }
    catch(error){
        // 5. 오류발생 시 이미지가 아닌 json으로 에러 전송
        console.error(error);
        res.send( {ret:-1, data:error} );
    }
});



// 다음글 (현재 7번이면 8번을 전달, 없으면 0전달)
// http://127.0.0.1:3000/board/nextno?_id=7
router.get('/nextno', async function(req, res, next) {
    try {
        // 0. 전달값 받기
        const _id = Number(req.query._id);

        // 1. db연결
        const dbconn   = await mongoclient.connect(mongourl);
        const collection = dbconn.db("id315").collection("board7");

        const query  = { _id : { $gt : _id } }
        const result = await collection.find(query, 
                        {projection:{ _id : 1 }} ) 
            .sort( { _id : 1 } )
            .limit(1)
            .toArray();
        console.log(result);

        var nno = 0; // 0으로 초기화
        if(result.length > 0) { // _id로 조회된 값을 변수에추가
            nno = result[0]._id;
        }

        // 3. 결과값 리턴
        res.send({ret:1, data:nno});
    }
    catch(error){
        console.error(error);
        res.send( {ret:-1, data:error} );
    }
});





// 이전글 (현재 7번이면 6번을 전달, 없으면 0전달)
// http://127.0.0.1:3000/board/prevno
router.get('/prevno', async function(req, res, next) {
    try{
        // 0.전달값 받기
        const _id = Number(req.query._id);

        // 1. db연결
        const dbconn = await mongoclient.connect(mongourl);
        var collection = dbconn.db("id315").collection("board7");

           // 2. 현재글번호보다 작은것중에서 가장큰값 1개
        // {$lt : 3}    // 3 미만
        // {$lte : 3}   // 3 이하
        // {$gt : 3}    // 3 초과
        // {$gte :3}    // 3 이상
        const query = {_id :{$lt : _id}};
        const result = await collection.find(query, {projection:{_id:1}}) 
            .sort({_id:-1})
            .limit(1)
            .toArray();
        console.log(result);

        var pno = 0; // 0으로 초기화
        if(result.length > 0) { // _id로 조회된 값을 변수에추가
            pno = result[0]._id;
        }

        // 3. 결과값 리턴
        res.send({ret:1, data:pno});
    }
    catch(error){
        console.error(error);
        res.send( {ret:-1, data:error} );
    }
});

// 상세내용
// http://127.0.0.1:3000/board/content?_id=7
router.get('/content', async function(req, res, next) {
    try{
        // 0.전달값 받기
        const _id = Number(req.query._id);

        // 1. db연결
        const dbconn = await mongoclient.connect(mongourl);
        var collection = dbconn.db("id315").collection("board7");

        // 2. 글번호가 해당하는 1개의 게시물 조회
        const query = {_id : _id};
        const row = await collection.findOne(query,{projection:{filename:0,filedata:0,filetype:0} });
        

        //조회된 값 리턴
        res.send({ret:1,data:row});
    }


  catch(error){
        console.error(error);
        res.send({ret:-1,data:error});
    }
});

// 게시판 삭제(글번호)
// http://127.0.0.1:3000/board/delete?_id=5
router.delete('/delete', async function(req, res, next) {
    try {
        // 0. 전달값 받기
        const _id = Number(req.query._id);

        // 1. db연결
        const dbconn   = await mongoclient.connect(mongourl);
        var collection = dbconn.db("id315").collection("board7");

        // 2. db삭제
        const query = { _id : _id };
        const result = await collection.deleteOne(query);
        console.log(result);

        // 3. 결과값 리턴
        res.send({ret:1, data:'게시물 삭제 성공'});
    }
    catch(error){
        console.error(error);
        res.send( {ret:-1, data:error} );
    }
});

// 게시판수정
// http://127.0.0.1:3000/board/update
router.put('/update', async function(req, res, next) {
    try{
        // 0 .전달값 받기
        // 조건을 위해서 글번호
        const _id = Number(req.body._id);
        const title = req.body.title;
        const content = req.body.content;

        const query = {_id:_id};
        const obj = { title, content};
   
    // 1.DB연동
    const dbconn     = await mongoclient.connect(mongourl);
    var collection = dbconn.db("id315").collection("board7");

    // 2.내용변경
    const result1 = await collection.updateOne(query,{$set:obj});
    console.log(result1);
    if(result1.modifiedCount === 1){
    // 3.결과값 리턴
    res.send({ret:1,data:'게시물 변경 완료'});
}
else {
    res.send({ret:0, data:'게시물 변경 실패'});
}
}

    catch(error){
        console.error(error);
        res.send({ret:-1,data:error});
    }
});


// 게시판목록
// http://127.0.0.1:3000/board/select?page=1&text=
router.get('/select', async function(req, res, next) {
    try{
        //0.전달값 받기
        const page = Number(req.query.page); // string -> number
        const text = req.query.text;

        //1. DB연결
        const dbconn     = await mongoclient.connect(mongourl);
        var collection = dbconn.db("id315").collection("board7");

        // 2. 조회
        const query = {title : new RegExp(text,'i')};
        const rows = await collection.find(query,{projection:{filename:0, filedata:0, filetype:0}})
        .sort({_id : -1})
        .skip((page-1)*10)
        .limit(10)
        .toArray();
        //3. 조회값 리턴
        res.send({ret:1, data:rows});
    }
    catch(error){
        console.error(error);
        res.send({ret:-1,data:error});
    }
});
//게시판 글쓰기
//(글번호(자동으로),제목, 내용, 작성자,조회수(1),이미지 ,작성일자
//http://127.0.0.1:3000/board/insert
//title, content, writer, file
router.post('/insert', upload.single("file"), async function(req, res, next) {
    try {
        // 0. mongodb 연결
        const dbconn     = await mongoclient.connect(mongourl);
        var collection = dbconn.db("id315").collection("counter7");

        // 1. counter7 컬렉션(테이블)에서 현재번호가져오고, 1증가시킴 
        const result = await collection.findOneAndUpdate(
            {_id:'SEQ_BOARD7_NO'}, { $inc : {seq : 1} });
        console.log(result);

        // 2. 추가할 데이터 생성    
        const _id      = result.value.seq; //글번호(자동으로)
        const title    = req.body.title;   //제목
        const content  = req.body.content;  
        const writer   = req.body.writer;
        const filename = req.file.originalname; 
        const filedata = req.file.buffer;  
        const filetype = req.file.mimetype; 
        const hit = 1;
        const regdate = new Date(); //UTC로 들어감. 9시간 느림

        // 3. object로 변환
        const obj  = { _id, title, content, writer, 
            filename, filedata, filetype, hit, regdate };
        
        // 4. DB에 저장
        collection = dbconn.db("id315").collection("board7");
        const result1 = await collection.insertOne(obj);
        console.log('result1',result1);

        // 5. 결과값 리턴    
        res.send( {ret:1, data:'글쓰기 성공했습니다.'} );
    }
    catch(error) {
        console.error(error);
        res.send( {ret:-1, data : error} ); //오류반환
    }
});

// 삭제 http://127.0.0.1:3000/board/delete?id=abc,  [body] name=bcd  
router.delete('/delete', function(req, res, next) {
    try {
        const id = req.query.id; //abc가 보관
        const name = req.body.name;// bcd가 보관
        res.send( {ret:1, data:'delete테스트', id:id, name:name} ); // 정상적인 결과반환
    }
    catch(error) {
        console.error(error);
        res.send( {ret:-1, data : error} ); //오류반환
    }
});

// 수정 http://127.0.0.1:3000/board/put?id=abc, [body] name=bcd 
router.put('/put', function(req, res, next) {
    try{
        const id = req.query.id // abc 보관
        const name = req.body.name; // bcd가 보관
        res.send({ret:1,data:'get테스트',id:id,name:name}); // 정상적인 결과반환

    }
    catch(err){
        console.log(error);
        res.send({ret:-1,data:error}); //오류반환
    }
    });



// 추가 http://127.0.0.1:3000/board/post?id=abc , [body] name= bcd
router.post('/post', function(req, res, next) {
    const id = req.query.id; //abc가 저정됨
    const name = req.body.name; //bcd가 저장됨
    const obj = {ret:1, data:'post테스트',id:id, name:name};
    res.send(obj);
});


// 조회 http://127.0.0.1:3000/board/get?id=abc
router.get('/get', function(req, res, next) {
    const id = req.query.id; // abc가 저장됨
    const obj = {ret:1, data:'get테스트',id:id};
    res.send(obj);
});

module.exports = router;
