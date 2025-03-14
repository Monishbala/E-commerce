import express from "express";
import {getAllProducts,getfeaturedProducts,createProduct,deleteProduct,getRecommendProducts,getProductsByCategory,toggleFeaturedProduct} from "../controllers/product.controller.js";
import { protectRoute,adminRoute } from "../middleware/auth.middleware.js";

const router = express.Router();

router.get("/",protectRoute,adminRoute,getAllProducts);
router.get("/featured",getfeaturedProducts);
router.get("/category/:category",getProductsByCategory);
router.get("/recommendations",getRecommendProducts);
router.post("/",protectRoute,adminRoute,createProduct);
router.patch("/:id",protectRoute,adminRoute,toggleFeaturedProduct);
router.delete("/:id",protectRoute,adminRoute,deleteProduct);

export default router;