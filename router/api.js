import {Router} from 'express'
import jwt from 'jsonwebtoken'
import retoken from './retoken'
import indexController from '../controllers'

const router = Router()
//设置跨域
router.all('*', function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Content-Type,Content-Length, Authorization, Accept,X-Requested-With");
  res.header("Access-Control-Allow-Methods","PUT,POST,GET,DELETE,OPTIONS");
  res.header("Access-Control-Request-Headers:content-type,xfilecategory,xfilename,xfilesize");
  res.header("X-Powered-By",' 3.2.1')
  if(req.method=="OPTIONS") res.send(200);/*让options请求快速返回*/
  else  next();
});
//添加token认证
router.use(retoken)

/**
 * 登录验证:
 * *首先获取提交的用户名和密码
 * *查询数据库是否存在账户名 存在则生成token
 * *
 * */
router.use('/login', (req, res, next) => {
  console.log('进入登录验证模块');
  //登录验证获取前端传来的用户表单用户名和密码参数
  let username = req.body.username ;
  let password = req.body.password ;
  console.log(username, password);
  
  

  //在数据库中查找用户的信息，如果找到说明用户存在 根据用户的数量来判断判断是否存在即可
  //使用数据库查询  User.count({'username': username ,'password':password})
  let count = 2;

    if(count > 1) {
      //生成秘钥
      var jwtTokenSecret = 'fjJWT' ;
      //生成token  
      const userToken = {
        username,
        password,
        loginAt: +new Date
      }
      //签发token 指定过期时间2h
      const token = jwt.sign(userToken, jwtTokenSecret, { expiresIn: '2h' });
      res.json({
        code: 200,
        data: token
      })
    }
})

router.use('/index', (req, res, next) => {
    res.json({
        code: 200,
        data: 'henhao'
    })
})
//路由
router.use('/user',indexController)
export default router