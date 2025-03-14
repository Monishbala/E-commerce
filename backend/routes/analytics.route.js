import express from "express";
import { adminRoute, protectRoute } from "../middleware/auth.middleware.js";
import {getAnalyticsData,getDailySalesData} from "../controllers/analytics.controller.js"

const router = express.Router();

router.get("/",protectRoute,adminRoute,async(req,res)=>{
    try {
        const analyticsData = await getAnalyticsData();

        
        const endDate = new Date();
        const startDate = new Date(endDate.getTime()-7*24*60*60*1000);

        const dailySales = await getDailySalesData(startDate,endDate);
        console.log(dailySales);

        res.json({
            analyticsData,
            dailySales
        })
    } catch (error) {
        console.log("Error in analytics route",error);

    }
})

export default router;