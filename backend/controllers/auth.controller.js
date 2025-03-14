import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import { redis } from "../lib/redis.js"; 


const generateTokens =(userId)=>{
    const accessToken = jwt.sign({userId},process.env.ACCESS_TOKEN_SECRET,{
        expiresIn:"15m"
    });

    const refreshToken = jwt.sign({userId},process.env.REFRESH_TOKEN_SECRET,{
        expiresIn:"7d"

    });

    return {accessToken,refreshToken};
}

const storeRefreshToken = async (userId, refreshToken) => {
    await redis.set(`refresh_token:${userId}`, refreshToken, "EX", 7 * 24 * 60 * 60);
};

const setCookies = (res,accessToken,refershToken)=>{
    res.cookie("accessToken",accessToken,{
        httpOnly:true,//XSS attack
        secure:process.env.NODE_ENV === "production",
        sameSite:"strict", //prevent csrf attack
        maxAge: 15 * 60 *1000
    })

    res.cookie("refreshToken",refershToken,{
        httpOnly:true,//XSS attack
        secure:process.env.NODE_ENV === "production",
        sameSite:"strict", //prevent csrf attack
        maxAge: 7 *24* 60 *60 *1000
    })
}


export const signup = async (req,res)=>{
    const {email,password,name} = req.body;


    if (!email || !password || !name) {
        return res.status(400).json({ message: "All fields are required" });
    }

    const userExist = await User.findOne({email});
    try {
        if(userExist)
            {
                return res.status(400).json({
                    message:"User already exist"
                });
            }
            const user = await User.create({
                name,
                email,
                password
            })

            // authenticate
            const {accessToken,refreshToken} = generateTokens(user._id);

            await storeRefreshToken(user._id,refreshToken);

            setCookies(res,accessToken,refreshToken);

            res.status(200).json({
                user:{
                    _id:user._id,
                    name:user.name,
                    email:user.email,
                    role:user.role,
                },
                message:"User created successfully"
            })
        
    } catch (error) {
        console.log("Erro in login controller",error.message);
        res.status(500).json({message:error.message})
    }
    
}

export const login = async (req,res)=>{
    try {
        
        const {email,password} = req.body;
        const user = await User.findOne({email});
        


        if(user && (await user.comparePassword(password)))
        {
            const {accessToken,refreshToken}= generateTokens(user._id);
            await storeRefreshToken(user._id,refreshToken);
            setCookies(res,accessToken,refreshToken);

            res.json({
                _id:user._id,
                name:user.name,
                email:user.name,
                role:user.role
            })
        }
        else{
            res.status(401).json({
                message:"invalid email or password"
            })
        }
    } catch (error) {
        console.log("Erro in login controller",error.message);
        res.status(500).json({
            message:error.message
        })
    }
}


export const logout = async (req,res)=>{
    try {
        const refreshToken = req.cookies.refreshToken;
        if(refreshToken)
        {
            const decode = jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET);
            await redis.del(`refresh_token:${decode.userId}`)
        }

        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        res.json({
            message:"logout successfull"
        })
    } catch (error) {
        console.log("Erro in login controller",error.message);
        res.status(500).message({
            message:"server error",
            error:error.message
        })
    }
}


export const refreshToken = async(req,res)=>{
    try {
        const refreshtoken = req.cookies.refreshToken;
        if(!refreshtoken)
        {
            return res.status(401).json({
                message:"No refresh token found"
            })
        }

        const decode= jwt.verify(refreshtoken,process.env.REFRESH_TOKEN_SECRET);
        const storedToken = await redis.get(`refresh_token:${decode.userId}`);

        if(storedToken!==refreshtoken)
        {
            return res.status(401).json({
                message:"Invalid refresh token"
            })
        }

        const accessToken = jwt.sign({userId:decode.userId},process.env.ACCESS_TOKEN_SECRET,{
            expiresIn:"15m"
        });

        res.cookie("accessToken",accessToken,{
            httpOnly:true,//XSS attack
            secure:process.env.NODE_ENV === "production",
            sameSite:"strict", //prevent csrf attack
            maxAge: 15 * 60 *1000
        })

        res.json({
            message:"Token refresh successfully"
        })
    } catch (error) {
        res.status(500).json({
            message:"Server error",
            error:error.message
        })
    }
}


export const getProfile= async(req,res)=>{
    try {


        res.json(req.user);
    } catch (error) {
        res.status(500).json({
            message:"Server error"
        })
    }
}