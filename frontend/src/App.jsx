import { Navigate,Route, Routes } from "react-router-dom"
import HomePage from "./pages/HomePage";
import SignUpPage from "./pages/SignUpPage";
import LoginPage from "./pages/LoginPage";
import Navbar from "./components/Navbar"
import { Toaster } from "react-hot-toast";
import { useUserStore } from "./stores/useUserStore";
import { use, useEffect } from "react";
import LoadingSpinner from "./components/LoadingSpinner";
import AdminPage from "./pages/AdminPage"
import CategoryPage from "./pages/CategoryPage";
import { useCartStore } from "./stores/useCartStore";
import CartPage from "./pages/CartPage";
import PurchaseSuccessPage from "./pages/PurchaseSuccessPage";
import PurchaseCancelPage from "./pages/PurchaseCancelPage "

function App() {
  const {user,checkAuth,checkingAuth}=useUserStore();
  const {getCartItems}=useCartStore()
  useEffect(()=>{
    checkAuth();
  },[checkAuth])

  useEffect(()=>{
    if(!user) return;
    getCartItems();
  },[getCartItems,user]);

  if(checkingAuth)
  {
    return <LoadingSpinner />
  }
  return (
    <div className="min-h-screen bg-gray-900 text-white overflow-hidden relative">
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute inset-0">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full 
              bg-[radial-gradient(ellipse_at_top,rgba(16,185,129,0.3)_0%,rgba(10,80,60,0.2)_45%,rgba(0,0,0,0.1)_100%)]">
            </div>
          </div>
        </div> 

       <div className="relative pt-20"></div> 
      <Navbar />
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/signup" element={!user?<SignUpPage />:<Navigate to="/" />} />
        <Route path="/login" element={!user?<LoginPage />:<Navigate to="/" />} />
        <Route path="/category/:category" element={<CategoryPage />} />
        <Route path="/cart" element={user?<CartPage />:<LoginPage />} />
        <Route path="/purchase-success" element={user?<PurchaseSuccessPage />:<LoginPage />} />
        <Route path="/purchase-cancel" element={user?<PurchaseCancelPage />:<LoginPage />} />
        <Route path="/secret-dashboard" element={user?.role==="admin"?<AdminPage />:<Navigate to="/login" />} />
      </Routes>
      <Toaster />
    </div>
  )
}

export default App
