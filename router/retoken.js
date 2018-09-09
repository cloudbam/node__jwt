import jwt from "jsonwebtoken";
import api from "./unLogin";
let unLogin = api.unLogin
export default function (req, res, next) {
  let method = req.method.toLowerCase()
  let path = req.path
    //接口不需要登陆：直接next
    //判断method类型，并且是否包含path
    if(unLogin[method] && unLogin[method].indexOf(path) !== -1){
      console.log('这个api 不需要验证token的')
      return  next()
    }
    const token = req.headers.authorization
    // console.log(req.headers)
  //没有token值，返回401
  //秘钥
  var jwtTokenSecret = 'fjJWT' ;

    if (!token) {
        return res.json({
            code: 401,
            msg: 'you need login:there is no token'
        })
    }

    /**
     * 解析token是否过期 和是否是正确的token
     */
    jwt.verify(token, jwtTokenSecret, (err, decoded) => {
        console.log('已验证token 是正确的')
        if(err){
            return res.json({
                code: 401,
                msg: err.msg
            })
        } else {
          // 将携带的信息赋给req.user
            req.user = decoded
            return next()
        }
    })
}