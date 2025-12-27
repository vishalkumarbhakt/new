/**
 * S2Cart API Client
 * Handles all API communication with the backend
 */

const API = {
    // Base URL configuration
    baseUrl: window.location.origin,
    
    // Auth token storage
    getToken() {
        return localStorage.getItem('s2cart_token');
    },
    
    setToken(token) {
        localStorage.setItem('s2cart_token', token);
    },
    
    removeToken() {
        localStorage.removeItem('s2cart_token');
        localStorage.removeItem('s2cart_user');
    },
    
    getUser() {
        const user = localStorage.getItem('s2cart_user');
        return user ? JSON.parse(user) : null;
    },
    
    setUser(user) {
        localStorage.setItem('s2cart_user', JSON.stringify(user));
    },
    
    isLoggedIn() {
        return !!this.getToken() && !!this.getUser();
    },
    
    // HTTP request helper
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const token = this.getToken();
        
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        try {
            const response = await fetch(url, {
                ...options,
                headers
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                // Handle token expiration
                if (response.status === 401) {
                    this.removeToken();
                    window.dispatchEvent(new Event('auth:logout'));
                }
                throw { status: response.status, data };
            }
            
            return data;
        } catch (error) {
            if (error.status) {
                throw error;
            }
            throw { status: 0, data: { error: 'Network error. Please check your connection.' } };
        }
    },
    
    // GET request
    async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    },
    
    // POST request
    async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },
    
    // PUT request
    async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    },
    
    // PATCH request
    async patch(endpoint, data) {
        return this.request(endpoint, {
            method: 'PATCH',
            body: JSON.stringify(data)
        });
    },
    
    // DELETE request
    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    },
    
    // ========================================
    // Authentication APIs
    // ========================================
    
    async login(credentials) {
        const response = await this.post('/api/auth/jwt/', credentials);
        if (response.access) {
            this.setToken(response.access);
            if (response.user) {
                this.setUser(response.user);
            }
        }
        return response;
    },
    
    async register(userData) {
        return this.post('/api/auth/register/', userData);
    },
    
    async logout() {
        try {
            const refreshToken = localStorage.getItem('s2cart_refresh_token');
            if (refreshToken) {
                await this.post('/api/auth/jwt/logout/', { refresh: refreshToken });
            }
        } catch {
            // Ignore logout errors
        }
        this.removeToken();
        localStorage.removeItem('s2cart_refresh_token');
    },
    
    async getProfile() {
        return this.get('/api/auth/profile/');
    },
    
    async updateProfile(data) {
        return this.patch('/api/auth/profile/update/', data);
    },
    
    async requestPasswordReset(email) {
        return this.post('/api/auth/password-reset/request/', { email });
    },
    
    async confirmPasswordReset(data) {
        return this.post('/api/auth/password-reset/confirm/', data);
    },
    
    async resendVerification(email) {
        return this.post('/api/auth/verify/resend/', { email });
    },
    
    // ========================================
    // Product APIs (Public)
    // ========================================
    
    async getCategories(params = {}) {
        let url = '/api/public/categories/';
        const queryParams = new URLSearchParams(params);
        if (queryParams.toString()) {
            url += `?${queryParams.toString()}`;
        }
        return this.get(url);
    },
    
    async getCategory(slug) {
        return this.get(`/api/public/categories/${slug}/`);
    },
    
    async getProducts(params = {}) {
        let url = '/api/public/products/';
        const queryParams = new URLSearchParams(params);
        if (queryParams.toString()) {
            url += `?${queryParams.toString()}`;
        }
        return this.get(url);
    },
    
    async getProduct(slug) {
        return this.get(`/api/public/products/${slug}/`);
    },
    
    async getProductReviews(slug) {
        return this.get(`/api/public/products/${slug}/reviews/`);
    },
    
    // ========================================
    // Wishlist APIs (Customer)
    // ========================================
    
    async getWishlist() {
        return this.get('/api/customer/wishlist/');
    },
    
    async addToWishlist(productId) {
        return this.post('/api/customer/wishlist/', { product_id: productId });
    },
    
    async removeFromWishlist(productId) {
        return this.delete(`/api/customer/wishlist/${productId}/`);
    },
    
    // ========================================
    // Cart APIs
    // ========================================
    
    async getCarts() {
        return this.get('/api/auth/carts/');
    },
    
    async getCartItems(storeId = null) {
        let url = '/api/auth/carts/items/';
        if (storeId) {
            url += `?store_id=${storeId}`;
        }
        return this.get(url);
    },
    
    async addToCart(item) {
        return this.post('/api/auth/carts/items/', item);
    },
    
    async updateCartItem(itemId, data) {
        return this.patch(`/api/auth/carts/items/${itemId}/`, data);
    },
    
    async removeFromCart(itemId) {
        return this.delete(`/api/auth/carts/items/${itemId}/`);
    },
    
    async clearCart(storeId = null) {
        let url = '/api/auth/carts/clear/';
        if (storeId) {
            url += `?store_id=${storeId}`;
        }
        return this.delete(url);
    },
    
    // ========================================
    // Order APIs
    // ========================================
    
    async getOrders() {
        return this.get('/api/auth/orders/');
    },
    
    async getOrder(orderId) {
        return this.get(`/api/auth/orders/${orderId}/`);
    },
    
    async createOrder(orderData) {
        return this.post('/api/auth/orders/', orderData);
    },
    
    async cancelOrder(orderId, reason) {
        return this.patch(`/api/auth/orders/${orderId}/`, {
            status: 'CANCELLED',
            cancellation_reason: reason
        });
    },
    
    // ========================================
    // Address APIs
    // ========================================
    
    async getAddresses() {
        return this.get('/api/auth/addresses/');
    },
    
    async addAddress(address) {
        return this.post('/api/auth/addresses/', address);
    },
    
    async updateAddress(addressId, address) {
        return this.patch(`/api/auth/addresses/${addressId}/`, address);
    },
    
    async deleteAddress(addressId) {
        return this.delete(`/api/auth/addresses/${addressId}/`);
    },
    
    async setDefaultAddress(addressId) {
        return this.post(`/api/auth/addresses/set-default/${addressId}/`);
    },
    
    // ========================================
    // Payment APIs
    // ========================================
    
    async initiatePayment(orderId, paymentMethod) {
        return this.post('/api/auth/payments/initiate/', {
            order_id: orderId,
            payment_method: paymentMethod
        });
    },
    
    async checkPaymentStatus(paymentId) {
        return this.get(`/api/auth/payments/status/${paymentId}/`);
    },
    
    async getPaymentHistory() {
        return this.get('/api/auth/payments/history/');
    }
};

// Export for use in other scripts
window.API = API;
