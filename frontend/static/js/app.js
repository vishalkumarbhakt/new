/**
 * S2Cart Frontend Application
 * Main application logic and UI handlers
 */

// ========================================
// App State
// ========================================
const AppState = {
    currentPage: 'home',
    cart: [],
    products: [],
    categories: [],
    currentProduct: null,
    currentCategory: null,
    searchQuery: '',
    sortBy: '-created_at'
};

// ========================================
// Initialization
// ========================================
document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

async function initApp() {
    // Check auth state
    updateAuthUI();
    
    // Load initial data
    await Promise.all([
        loadCategories(),
        loadFeaturedProducts(),
        loadNewArrivals()
    ]);
    
    // Update cart count
    await updateCartCount();
    
    // Listen for auth changes
    window.addEventListener('auth:logout', () => {
        updateAuthUI();
        showPage('login');
    });
}

// ========================================
// Page Navigation
// ========================================
function showPage(pageName, data = null) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
        page.classList.add('hidden');
    });
    
    // Show selected page
    const page = document.getElementById(`${pageName}Page`);
    if (page) {
        page.classList.remove('hidden');
        page.classList.add('active');
        AppState.currentPage = pageName;
        
        // Load page-specific content
        switch (pageName) {
            case 'home':
                // Already loaded
                break;
            case 'categories':
                loadAllCategories();
                break;
            case 'products':
                if (data) {
                    loadProductsByCategory(data);
                }
                break;
            case 'productDetail':
                if (data) {
                    loadProductDetail(data);
                }
                break;
            case 'cart':
                loadCart();
                break;
            case 'profile':
                loadProfile();
                break;
            case 'orders':
                loadOrders();
                break;
            case 'wishlist':
                loadWishlist();
                break;
        }
    }
    
    // Scroll to top
    window.scrollTo(0, 0);
    
    // Close mobile menu if open
    const mobileMenu = document.getElementById('mobileMenu');
    if (mobileMenu && !mobileMenu.classList.contains('hidden')) {
        mobileMenu.classList.add('hidden');
    }
}

// ========================================
// Auth UI Updates
// ========================================
function updateAuthUI() {
    const isLoggedIn = API.isLoggedIn();
    const user = API.getUser();
    
    // Desktop nav
    const authLinks = document.getElementById('authLinks');
    const userMenu = document.getElementById('userMenu');
    
    // Mobile nav
    const mobileAuthLinks = document.getElementById('mobileAuthLinks');
    const mobileUserMenu = document.getElementById('mobileUserMenu');
    
    if (isLoggedIn && user) {
        // Show user menu, hide auth links
        authLinks.classList.add('hidden');
        userMenu.classList.remove('hidden');
        mobileAuthLinks.classList.add('hidden');
        mobileUserMenu.classList.remove('hidden');
        
        // Update user name
        document.getElementById('userName').textContent = user.first_name || user.username;
    } else {
        // Show auth links, hide user menu
        authLinks.classList.remove('hidden');
        userMenu.classList.add('hidden');
        mobileAuthLinks.classList.remove('hidden');
        mobileUserMenu.classList.add('hidden');
    }
}

function toggleUserDropdown() {
    const dropdown = document.getElementById('userDropdown');
    dropdown.classList.toggle('hidden');
}

function toggleMobileMenu() {
    const mobileMenu = document.getElementById('mobileMenu');
    mobileMenu.classList.toggle('hidden');
}

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
    const userMenu = document.querySelector('.user-menu');
    const dropdown = document.getElementById('userDropdown');
    
    if (userMenu && dropdown && !userMenu.contains(e.target)) {
        dropdown.classList.add('hidden');
    }
});

// ========================================
// Authentication Handlers
// ========================================
async function handleLogin(event) {
    event.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    showLoading();
    
    try {
        const response = await API.login({ email, password });
        
        if (response.refresh) {
            localStorage.setItem('s2cart_refresh_token', response.refresh);
        }
        
        hideLoading();
        showToast('Login successful!', 'success');
        updateAuthUI();
        await updateCartCount();
        showPage('home');
        
    } catch (error) {
        hideLoading();
        const message = error.data?.error || error.data?.detail || 'Login failed. Please try again.';
        showToast(message, 'error');
    }
}

async function handleRegister(event) {
    event.preventDefault();
    
    const password = document.getElementById('regPassword').value;
    const confirmPassword = document.getElementById('regConfirmPassword').value;
    
    if (password !== confirmPassword) {
        showToast('Passwords do not match!', 'error');
        return;
    }
    
    const userData = {
        username: document.getElementById('regUsername').value,
        email: document.getElementById('regEmail').value,
        password: password,
        first_name: document.getElementById('regFirstName').value,
        last_name: document.getElementById('regLastName').value,
        phone_number: document.getElementById('regPhone').value
    };
    
    showLoading();
    
    try {
        const response = await API.register(userData);
        hideLoading();
        
        if (response.data?.token) {
            API.setToken(response.data.token);
            if (response.data.user) {
                API.setUser(response.data.user);
            }
        }
        
        showToast('Registration successful! Please check your email for verification.', 'success');
        showPage('login');
        
    } catch (error) {
        hideLoading();
        let message = 'Registration failed. Please try again.';
        if (error.data) {
            if (error.data.username) message = error.data.username[0];
            else if (error.data.email) message = error.data.email[0];
            else if (error.data.password) message = error.data.password[0];
            else if (error.data.error) message = error.data.error;
        }
        showToast(message, 'error');
    }
}

async function handleForgotPassword(event) {
    event.preventDefault();
    
    const email = document.getElementById('resetEmail').value;
    
    showLoading();
    
    try {
        await API.requestPasswordReset(email);
        hideLoading();
        showToast('If your email exists, you will receive password reset instructions.', 'success');
        showPage('login');
        
    } catch (error) {
        hideLoading();
        showToast('Failed to send reset email. Please try again.', 'error');
    }
}

async function logout() {
    showLoading();
    
    try {
        await API.logout();
    } catch {
        // Ignore errors
    }
    
    hideLoading();
    updateAuthUI();
    showToast('Logged out successfully', 'success');
    showPage('home');
}

// ========================================
// Category Functions
// ========================================
async function loadCategories() {
    try {
        const response = await API.getCategories({ featured: 'true' });
        const categories = response.results || response || [];
        AppState.categories = categories;
        renderFeaturedCategories(categories.slice(0, 6));
    } catch (error) {
        console.error('Failed to load categories:', error);
    }
}

async function loadAllCategories() {
    const container = document.getElementById('allCategories');
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
    
    try {
        const response = await API.getCategories();
        const categories = response.results || response || [];
        renderCategories(container, categories);
    } catch (error) {
        container.innerHTML = '<p class="text-center">Failed to load categories.</p>';
    }
}

function renderFeaturedCategories(categories) {
    const container = document.getElementById('featuredCategories');
    renderCategories(container, categories);
}

function renderCategories(container, categories) {
    if (!categories || categories.length === 0) {
        container.innerHTML = '<p class="text-center">No categories found.</p>';
        return;
    }
    
    container.innerHTML = categories.map(category => `
        <div class="category-card" onclick="showProducts('${category.slug}', '${escapeHtml(category.name)}')">
            <img src="${category.image || getPlaceholderImage('category')}" alt="${escapeHtml(category.name)}">
            <div class="category-card-body">
                <h3>${escapeHtml(category.name)}</h3>
                <p>${category.product_count || 0} products</p>
            </div>
        </div>
    `).join('');
}

function showProducts(categorySlug, categoryName) {
    AppState.currentCategory = categorySlug;
    document.getElementById('productsPageTitle').textContent = categoryName;
    showPage('products', categorySlug);
}

// ========================================
// Product Functions
// ========================================
async function loadFeaturedProducts() {
    try {
        const response = await API.getProducts({ featured: 'true', per_page: 8 });
        const products = response.results || response || [];
        renderProducts('featuredProducts', products);
    } catch (error) {
        console.error('Failed to load featured products:', error);
    }
}

async function loadNewArrivals() {
    try {
        const response = await API.getProducts({ new: 'true', per_page: 8 });
        const products = response.results || response || [];
        renderProducts('newArrivals', products);
    } catch (error) {
        console.error('Failed to load new arrivals:', error);
    }
}

async function loadProductsByCategory(categorySlug) {
    const container = document.getElementById('productsList');
    const loading = document.getElementById('productsLoading');
    
    container.innerHTML = '';
    loading.classList.remove('hidden');
    
    try {
        const params = { category: categorySlug };
        if (AppState.sortBy) {
            params.ordering = AppState.sortBy;
        }
        
        const response = await API.getProducts(params);
        const products = response.results || response || [];
        AppState.products = products;
        
        loading.classList.add('hidden');
        renderProducts('productsList', products);
        
    } catch (error) {
        loading.classList.add('hidden');
        container.innerHTML = '<p class="text-center">Failed to load products.</p>';
    }
}

async function searchProducts() {
    const query = document.getElementById('searchInput').value.trim();
    if (!query) return;
    
    AppState.searchQuery = query;
    document.getElementById('productsPageTitle').textContent = `Search: "${query}"`;
    showPage('products');
    
    const container = document.getElementById('productsList');
    const loading = document.getElementById('productsLoading');
    
    container.innerHTML = '';
    loading.classList.remove('hidden');
    
    try {
        const response = await API.getProducts({ search: query });
        const products = response.results || response || [];
        
        loading.classList.add('hidden');
        renderProducts('productsList', products);
        
    } catch (error) {
        loading.classList.add('hidden');
        container.innerHTML = '<p class="text-center">Failed to search products.</p>';
    }
}

function sortProducts() {
    AppState.sortBy = document.getElementById('sortSelect').value;
    if (AppState.currentCategory) {
        loadProductsByCategory(AppState.currentCategory);
    } else if (AppState.searchQuery) {
        searchProducts();
    }
}

function renderProducts(containerId, products) {
    const container = document.getElementById(containerId);
    
    if (!products || products.length === 0) {
        container.innerHTML = '<p class="text-center">No products found.</p>';
        return;
    }
    
    container.innerHTML = products.map(product => `
        <div class="product-card">
            ${product.is_new ? '<span class="product-badge new">New</span>' : ''}
            ${product.is_featured ? '<span class="product-badge featured">Featured</span>' : ''}
            ${product.discount_percentage && !product.is_new ? `<span class="product-badge">${Math.round(product.discount_percentage)}% OFF</span>` : ''}
            
            <button class="product-wishlist" onclick="toggleWishlist(event, ${product.id})">
                <i class="far fa-heart"></i>
            </button>
            
            <img class="product-image" 
                 src="${product.primary_image?.image || getPlaceholderImage('product')}" 
                 alt="${escapeHtml(product.name)}"
                 onclick="showProductDetail('${product.slug}')">
            
            <div class="product-info">
                <span class="product-category">${escapeHtml(product.category?.name || '')}</span>
                <h3 class="product-name" onclick="showProductDetail('${product.slug}')">${escapeHtml(product.name)}</h3>
                
                <div class="product-price">
                    <span class="current-price">₹${formatPrice(product.effective_price || product.price)}</span>
                    ${product.discount_price ? `<span class="original-price">₹${formatPrice(product.price)}</span>` : ''}
                    ${product.discount_percentage ? `<span class="discount-percent">${Math.round(product.discount_percentage)}% off</span>` : ''}
                </div>
                
                <div class="product-rating">
                    ${renderStars(product.average_rating || 0)}
                    <span>(${product.review_count || 0})</span>
                </div>
                
                <div class="product-actions">
                    <button class="btn btn-primary btn-sm" onclick="quickAddToCart(${product.id}, '${escapeHtml(product.name)}', ${product.effective_price || product.price})">
                        <i class="fas fa-shopping-cart"></i> Add to Cart
                    </button>
                </div>
            </div>
        </div>
    `).join('');
}

function showProductDetail(slug) {
    showPage('productDetail', slug);
}

async function loadProductDetail(slug) {
    const container = document.getElementById('productDetail');
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
    
    try {
        const product = await API.getProduct(slug);
        AppState.currentProduct = product;
        renderProductDetail(product);
        
    } catch (error) {
        container.innerHTML = '<p class="text-center">Failed to load product details.</p>';
    }
}

function renderProductDetail(product) {
    const container = document.getElementById('productDetail');
    
    const images = product.images || [];
    const mainImage = images.find(img => img.is_primary) || images[0];
    
    container.innerHTML = `
        <div class="product-detail-grid">
            <div class="product-gallery">
                <img class="product-main-image" id="mainProductImage" 
                     src="${mainImage?.image || getPlaceholderImage('product')}" 
                     alt="${escapeHtml(product.name)}">
                
                ${images.length > 1 ? `
                    <div class="product-thumbnails">
                        ${images.map((img, index) => `
                            <img class="product-thumbnail ${index === 0 ? 'active' : ''}" 
                                 src="${img.image}" 
                                 alt="${escapeHtml(product.name)}"
                                 onclick="changeMainImage('${img.image}', this)">
                        `).join('')}
                    </div>
                ` : ''}
            </div>
            
            <div class="product-detail-info">
                <span class="product-detail-category">${escapeHtml(product.category?.name || '')}</span>
                <h1>${escapeHtml(product.name)}</h1>
                
                <div class="product-rating">
                    ${renderStars(product.average_rating || 0)}
                    <span>(${product.review_count || 0} reviews)</span>
                </div>
                
                <div class="product-detail-price">
                    <span class="current-price">₹${formatPrice(product.effective_price || product.price)}</span>
                    ${product.discount_price ? `
                        <span class="original-price">₹${formatPrice(product.price)}</span>
                        <span class="discount-percent">Save ${Math.round(product.discount_percentage)}%</span>
                    ` : ''}
                </div>
                
                <p class="product-description">${escapeHtml(product.description || 'No description available.')}</p>
                
                <div class="quantity-selector">
                    <label>Quantity:</label>
                    <div class="quantity-controls">
                        <button onclick="updateQuantity(-1)">-</button>
                        <input type="number" id="productQuantity" value="1" min="1" max="${product.stock_quantity || 99}">
                        <button onclick="updateQuantity(1)">+</button>
                    </div>
                </div>
                
                <div class="product-detail-actions">
                    <button class="btn btn-primary btn-lg" onclick="addProductToCart()">
                        <i class="fas fa-shopping-cart"></i> Add to Cart
                    </button>
                    <button class="btn btn-outline btn-lg" onclick="toggleWishlist(event, ${product.id})">
                        <i class="far fa-heart"></i> Wishlist
                    </button>
                </div>
                
                <div class="product-meta">
                    <p><strong>SKU:</strong> ${escapeHtml(product.sku)}</p>
                    <p><strong>Brand:</strong> ${escapeHtml(product.brand || 'N/A')}</p>
                    <p><strong>Availability:</strong> ${product.is_in_stock ? '<span style="color: var(--secondary-color);">In Stock</span>' : '<span style="color: var(--danger-color);">Out of Stock</span>'}</p>
                    ${product.stock_quantity ? `<p><strong>Stock:</strong> ${product.stock_quantity} items left</p>` : ''}
                </div>
            </div>
        </div>
    `;
}

function changeMainImage(src, thumbnail) {
    document.getElementById('mainProductImage').src = src;
    document.querySelectorAll('.product-thumbnail').forEach(t => t.classList.remove('active'));
    thumbnail.classList.add('active');
}

function updateQuantity(delta) {
    const input = document.getElementById('productQuantity');
    const newValue = Math.max(1, parseInt(input.value) + delta);
    const max = parseInt(input.max) || 99;
    input.value = Math.min(newValue, max);
}

// ========================================
// Cart Functions
// ========================================
async function quickAddToCart(productId, productName, price) {
    if (!API.isLoggedIn()) {
        showToast('Please login to add items to cart', 'error');
        showPage('login');
        return;
    }
    
    try {
        await API.addToCart({
            store_id: 'default',
            product_id: productId.toString(),
            product_name: productName,
            quantity: 1,
            unit_price: price
        });
        
        showToast('Added to cart!', 'success');
        await updateCartCount();
        
    } catch (error) {
        const message = error.data?.message || error.data?.error || 'Failed to add to cart';
        showToast(message, 'error');
    }
}

async function addProductToCart() {
    if (!API.isLoggedIn()) {
        showToast('Please login to add items to cart', 'error');
        showPage('login');
        return;
    }
    
    const product = AppState.currentProduct;
    if (!product) return;
    
    const quantity = parseInt(document.getElementById('productQuantity').value);
    
    showLoading();
    
    try {
        await API.addToCart({
            store_id: 'default',
            product_id: product.id.toString(),
            product_name: product.name,
            product_image_url: product.primary_image?.image || '',
            quantity: quantity,
            unit_price: product.effective_price || product.price
        });
        
        hideLoading();
        showToast('Added to cart!', 'success');
        await updateCartCount();
        
    } catch (error) {
        hideLoading();
        const message = error.data?.message || error.data?.error || 'Failed to add to cart';
        showToast(message, 'error');
    }
}

async function updateCartCount() {
    if (!API.isLoggedIn()) {
        document.getElementById('cartCount').textContent = '0';
        return;
    }
    
    try {
        const response = await API.getCartItems();
        const items = response.data?.stores?.[0]?.items || response.data?.items || [];
        const count = items.reduce((sum, item) => sum + (item.quantity || 0), 0);
        document.getElementById('cartCount').textContent = count.toString();
    } catch {
        document.getElementById('cartCount').textContent = '0';
    }
}

async function loadCart() {
    const container = document.getElementById('cartContent');
    
    if (!API.isLoggedIn()) {
        container.innerHTML = `
            <div class="cart-empty">
                <i class="fas fa-shopping-cart"></i>
                <h3>Please Login</h3>
                <p>You need to be logged in to view your cart.</p>
                <button class="btn btn-primary" onclick="showPage('login')">Login</button>
            </div>
        `;
        return;
    }
    
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
    
    try {
        const response = await API.getCartItems();
        const stores = response.data?.stores || [];
        const items = stores[0]?.items || response.data?.items || [];
        
        if (items.length === 0) {
            container.innerHTML = `
                <div class="cart-empty">
                    <i class="fas fa-shopping-cart"></i>
                    <h3>Your cart is empty</h3>
                    <p>Looks like you haven't added anything to your cart yet.</p>
                    <button class="btn btn-primary" onclick="showPage('home')">Continue Shopping</button>
                </div>
            `;
            return;
        }
        
        AppState.cart = items;
        renderCart(items);
        
    } catch (error) {
        container.innerHTML = '<p class="text-center">Failed to load cart.</p>';
    }
}

function renderCart(items) {
    const container = document.getElementById('cartContent');
    
    const subtotal = items.reduce((sum, item) => sum + (parseFloat(item.total_price) || 0), 0);
    const shipping = subtotal > 500 ? 0 : 50;
    const total = subtotal + shipping;
    
    container.innerHTML = `
        <div class="cart-items">
            ${items.map(item => `
                <div class="cart-item">
                    <img class="cart-item-image" 
                         src="${item.product_image_url || getPlaceholderImage('product')}" 
                         alt="${escapeHtml(item.product_name)}">
                    <div class="cart-item-details">
                        <h4 class="cart-item-name">${escapeHtml(item.product_name)}</h4>
                        <p class="cart-item-price">₹${formatPrice(item.unit_price)}</p>
                        <div class="cart-item-actions">
                            <div class="quantity-controls">
                                <button onclick="updateCartItemQuantity(${item.id}, ${item.quantity - 1})">-</button>
                                <input type="number" value="${item.quantity}" readonly>
                                <button onclick="updateCartItemQuantity(${item.id}, ${item.quantity + 1})">+</button>
                            </div>
                            <span class="cart-item-remove" onclick="removeCartItem(${item.id})">
                                <i class="fas fa-trash"></i> Remove
                            </span>
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
        
        <div class="cart-summary">
            <h3>Order Summary</h3>
            <div class="cart-summary-row">
                <span>Subtotal (${items.length} items)</span>
                <span>₹${formatPrice(subtotal)}</span>
            </div>
            <div class="cart-summary-row">
                <span>Shipping</span>
                <span>${shipping === 0 ? 'Free' : '₹' + formatPrice(shipping)}</span>
            </div>
            ${subtotal < 500 ? `
                <div class="cart-summary-row" style="color: var(--secondary-color); font-size: 0.875rem;">
                    <span>Add ₹${formatPrice(500 - subtotal)} more for free shipping!</span>
                </div>
            ` : ''}
            <div class="cart-summary-row total">
                <span>Total</span>
                <span>₹${formatPrice(total)}</span>
            </div>
            <button class="btn btn-primary btn-block" onclick="proceedToCheckout()" style="margin-top: 1rem;">
                Proceed to Checkout
            </button>
            <button class="btn btn-secondary btn-block" onclick="showPage('home')" style="margin-top: 0.5rem;">
                Continue Shopping
            </button>
        </div>
    `;
}

async function updateCartItemQuantity(itemId, newQuantity) {
    if (newQuantity < 1) {
        removeCartItem(itemId);
        return;
    }
    
    try {
        await API.updateCartItem(itemId, { quantity: newQuantity });
        await loadCart();
        await updateCartCount();
    } catch (error) {
        showToast('Failed to update quantity', 'error');
    }
}

async function removeCartItem(itemId) {
    try {
        await API.removeFromCart(itemId);
        showToast('Item removed from cart', 'success');
        await loadCart();
        await updateCartCount();
    } catch (error) {
        showToast('Failed to remove item', 'error');
    }
}

function proceedToCheckout() {
    showToast('Checkout functionality coming soon!', 'success');
}

// ========================================
// Wishlist Functions
// ========================================
async function toggleWishlist(event, productId) {
    event.stopPropagation();
    
    if (!API.isLoggedIn()) {
        showToast('Please login to use wishlist', 'error');
        showPage('login');
        return;
    }
    
    const button = event.currentTarget;
    const icon = button.querySelector('i');
    
    try {
        if (button.classList.contains('active')) {
            await API.removeFromWishlist(productId);
            button.classList.remove('active');
            icon.classList.replace('fas', 'far');
            showToast('Removed from wishlist', 'success');
        } else {
            await API.addToWishlist(productId);
            button.classList.add('active');
            icon.classList.replace('far', 'fas');
            showToast('Added to wishlist!', 'success');
        }
    } catch (error) {
        showToast('Failed to update wishlist', 'error');
    }
}

async function loadWishlist() {
    const container = document.getElementById('wishlistContent');
    
    if (!API.isLoggedIn()) {
        container.innerHTML = `
            <div class="cart-empty">
                <i class="fas fa-heart"></i>
                <h3>Please Login</h3>
                <p>You need to be logged in to view your wishlist.</p>
                <button class="btn btn-primary" onclick="showPage('login')">Login</button>
            </div>
        `;
        return;
    }
    
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
    
    try {
        const response = await API.getWishlist();
        const items = response.results || response || [];
        
        if (items.length === 0) {
            container.innerHTML = `
                <div class="cart-empty" style="grid-column: 1 / -1;">
                    <i class="fas fa-heart"></i>
                    <h3>Your wishlist is empty</h3>
                    <p>Save items you love to your wishlist.</p>
                    <button class="btn btn-primary" onclick="showPage('home')">Browse Products</button>
                </div>
            `;
            return;
        }
        
        // Render wishlist items as product cards
        container.innerHTML = items.map(item => {
            const product = item.product;
            return `
                <div class="product-card">
                    <button class="product-wishlist active" onclick="removeFromWishlist(event, ${product.id})">
                        <i class="fas fa-heart"></i>
                    </button>
                    
                    <img class="product-image" 
                         src="${product.primary_image?.image || getPlaceholderImage('product')}" 
                         alt="${escapeHtml(product.name)}"
                         onclick="showProductDetail('${product.slug}')">
                    
                    <div class="product-info">
                        <h3 class="product-name" onclick="showProductDetail('${product.slug}')">${escapeHtml(product.name)}</h3>
                        
                        <div class="product-price">
                            <span class="current-price">₹${formatPrice(product.effective_price || product.price)}</span>
                        </div>
                        
                        <div class="product-actions">
                            <button class="btn btn-primary btn-sm" onclick="quickAddToCart(${product.id}, '${escapeHtml(product.name)}', ${product.effective_price || product.price})">
                                <i class="fas fa-shopping-cart"></i> Add to Cart
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        container.innerHTML = '<p class="text-center">Failed to load wishlist.</p>';
    }
}

async function removeFromWishlist(event, productId) {
    event.stopPropagation();
    
    try {
        await API.removeFromWishlist(productId);
        showToast('Removed from wishlist', 'success');
        loadWishlist();
    } catch (error) {
        showToast('Failed to remove from wishlist', 'error');
    }
}

// ========================================
// Profile Functions
// ========================================
async function loadProfile() {
    const container = document.getElementById('profileContent');
    
    if (!API.isLoggedIn()) {
        container.innerHTML = `
            <div class="cart-empty">
                <i class="fas fa-user"></i>
                <h3>Please Login</h3>
                <p>You need to be logged in to view your profile.</p>
                <button class="btn btn-primary" onclick="showPage('login')">Login</button>
            </div>
        `;
        return;
    }
    
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
    
    try {
        const user = await API.getProfile();
        renderProfile(user);
        
    } catch (error) {
        container.innerHTML = '<p class="text-center">Failed to load profile.</p>';
    }
}

function renderProfile(user) {
    const container = document.getElementById('profileContent');
    
    container.innerHTML = `
        <div class="profile-sidebar">
            <img class="profile-avatar" src="${user.profile_image || getPlaceholderImage('avatar')}" alt="Profile">
            <h3 class="profile-name">${escapeHtml(user.first_name || '')} ${escapeHtml(user.last_name || '')}</h3>
            <p class="profile-email">${escapeHtml(user.email)}</p>
            <nav class="profile-nav">
                <a href="#" class="active"><i class="fas fa-user"></i> Account Info</a>
                <a href="#" onclick="showPage('orders')"><i class="fas fa-box"></i> My Orders</a>
                <a href="#" onclick="showPage('wishlist')"><i class="fas fa-heart"></i> Wishlist</a>
            </nav>
        </div>
        
        <div class="profile-main">
            <h3>Account Information</h3>
            <form id="profileForm" onsubmit="updateProfile(event)">
                <div class="form-row">
                    <div class="form-group">
                        <label>First Name</label>
                        <input type="text" id="profileFirstName" value="${escapeHtml(user.first_name || '')}">
                    </div>
                    <div class="form-group">
                        <label>Last Name</label>
                        <input type="text" id="profileLastName" value="${escapeHtml(user.last_name || '')}">
                    </div>
                </div>
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" value="${escapeHtml(user.username)}" disabled>
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" value="${escapeHtml(user.email)}" disabled>
                </div>
                <div class="form-group">
                    <label>Phone Number</label>
                    <input type="tel" id="profilePhone" value="${escapeHtml(user.phone_number || '')}">
                </div>
                <button type="submit" class="btn btn-primary">Save Changes</button>
            </form>
        </div>
    `;
}

async function updateProfile(event) {
    event.preventDefault();
    
    const data = {
        first_name: document.getElementById('profileFirstName').value,
        last_name: document.getElementById('profileLastName').value,
        phone_number: document.getElementById('profilePhone').value
    };
    
    showLoading();
    
    try {
        const updatedUser = await API.updateProfile(data);
        API.setUser(updatedUser);
        hideLoading();
        showToast('Profile updated successfully!', 'success');
        updateAuthUI();
        
    } catch (error) {
        hideLoading();
        showToast('Failed to update profile', 'error');
    }
}

// ========================================
// Orders Functions
// ========================================
async function loadOrders() {
    const container = document.getElementById('ordersContent');
    
    if (!API.isLoggedIn()) {
        container.innerHTML = `
            <div class="cart-empty">
                <i class="fas fa-box"></i>
                <h3>Please Login</h3>
                <p>You need to be logged in to view your orders.</p>
                <button class="btn btn-primary" onclick="showPage('login')">Login</button>
            </div>
        `;
        return;
    }
    
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
    
    try {
        const response = await API.getOrders();
        const orders = response.results || response || [];
        
        if (orders.length === 0) {
            container.innerHTML = `
                <div class="cart-empty">
                    <i class="fas fa-box-open"></i>
                    <h3>No orders yet</h3>
                    <p>You haven't placed any orders yet.</p>
                    <button class="btn btn-primary" onclick="showPage('home')">Start Shopping</button>
                </div>
            `;
            return;
        }
        
        renderOrders(orders);
        
    } catch (error) {
        container.innerHTML = '<p class="text-center">Failed to load orders.</p>';
    }
}

function renderOrders(orders) {
    const container = document.getElementById('ordersContent');
    
    container.innerHTML = orders.map(order => `
        <div class="order-card">
            <div class="order-header">
                <div class="order-info">
                    <p>Order #${escapeHtml(order.order_number)}</p>
                    <p>Placed on ${formatDate(order.order_date)}</p>
                </div>
                <span class="order-status ${order.status.toLowerCase()}">${order.status}</span>
            </div>
            
            <div class="order-items">
                ${(order.items || []).slice(0, 2).map(item => `
                    <div class="order-item">
                        <img class="order-item-image" 
                             src="${item.product_image_url || getPlaceholderImage('product')}" 
                             alt="${escapeHtml(item.product_name)}">
                        <div class="order-item-details">
                            <p><strong>${escapeHtml(item.product_name)}</strong></p>
                            <p>Qty: ${item.quantity} × ₹${formatPrice(item.unit_price)}</p>
                        </div>
                    </div>
                `).join('')}
                ${order.items?.length > 2 ? `<p style="color: var(--text-secondary); font-size: 0.875rem;">+${order.items.length - 2} more items</p>` : ''}
            </div>
            
            <div class="order-footer">
                <span class="order-total">Total: ₹${formatPrice(order.total_amount)}</span>
                <button class="btn btn-secondary btn-sm" onclick="viewOrderDetails(${order.id})">View Details</button>
            </div>
        </div>
    `).join('');
}

function viewOrderDetails(orderId) {
    showToast('Order details coming soon!', 'success');
}

// ========================================
// Utility Functions
// ========================================
function showLoading() {
    document.getElementById('loadingOverlay').classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('loadingOverlay').classList.add('hidden');
}

function showToast(message, type = '') {
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toastMessage');
    
    toast.className = 'toast';
    if (type) toast.classList.add(type);
    toastMessage.textContent = message;
    toast.classList.remove('hidden');
    
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 3000);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatPrice(price) {
    if (!price) return '0.00';
    return parseFloat(price).toLocaleString('en-IN', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    });
}

function formatDate(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-IN', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function renderStars(rating) {
    const fullStars = Math.floor(rating);
    const hasHalfStar = rating % 1 >= 0.5;
    const emptyStars = 5 - fullStars - (hasHalfStar ? 1 : 0);
    
    let stars = '';
    for (let i = 0; i < fullStars; i++) {
        stars += '<i class="fas fa-star"></i>';
    }
    if (hasHalfStar) {
        stars += '<i class="fas fa-star-half-alt"></i>';
    }
    for (let i = 0; i < emptyStars; i++) {
        stars += '<i class="far fa-star"></i>';
    }
    
    return stars;
}

function getPlaceholderImage(type) {
    const placeholders = {
        product: 'https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=400&h=400&fit=crop',
        category: 'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=400&h=300&fit=crop',
        avatar: 'https://images.unsplash.com/photo-1633332755192-727a05c4013d?w=120&h=120&fit=crop'
    };
    return placeholders[type] || placeholders.product;
}

// Scroll to offers section
function scrollToOffers() {
    const offersSection = document.getElementById('offersSection');
    if (offersSection) {
        offersSection.scrollIntoView({ behavior: 'smooth' });
    }
}

// Newsletter subscription
function subscribeNewsletter(event) {
    event.preventDefault();
    showToast('Thank you for subscribing!', 'success');
    event.target.reset();
}

// Countdown timer for deals
function startCountdown() {
    const updateTimer = () => {
        const now = new Date();
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(0, 0, 0, 0);
        
        let diff = tomorrow - now;
        
        // Handle edge case when diff is negative or zero
        if (diff <= 0) {
            diff = 24 * 60 * 60 * 1000; // Reset to 24 hours
        }
        
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);
        
        const hoursEl = document.getElementById('hours');
        const minutesEl = document.getElementById('minutes');
        const secondsEl = document.getElementById('seconds');
        
        if (hoursEl) hoursEl.textContent = hours.toString().padStart(2, '0');
        if (minutesEl) minutesEl.textContent = minutes.toString().padStart(2, '0');
        if (secondsEl) secondsEl.textContent = seconds.toString().padStart(2, '0');
    };
    
    updateTimer();
    setInterval(updateTimer, 1000);
}

// Start countdown on page load
document.addEventListener('DOMContentLoaded', startCountdown);

// Handle Enter key in search
document.getElementById('searchInput')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        searchProducts();
    }
});
