"""
URL configuration for products app.
Organized into public, customer, and admin namespaces.
"""
from django.urls import path
from .views import (
    # Public views
    PublicCategoryListView, PublicCategoryDetailView,
    PublicProductListView, PublicProductDetailView, PublicProductReviewsView,
    # Customer views
    CustomerProductReviewCreateView, CustomerWishlistListView, CustomerWishlistDeleteView,
    # Admin views
    AdminCategoryListCreateView, AdminCategoryDetailView,
    AdminProductListCreateView, AdminProductDetailView,
    AdminProductImageUploadView, AdminProductImageDeleteView, AdminProductStockUpdateView
)

# Public API URLs - No authentication required
public_urlpatterns = [
    # Categories
    path('categories/', PublicCategoryListView.as_view(), name='public_category_list'),
    path('categories/<slug:slug>/', PublicCategoryDetailView.as_view(), name='public_category_detail'),
    
    # Products
    path('products/', PublicProductListView.as_view(), name='public_product_list'),
    path('products/<slug:slug>/', PublicProductDetailView.as_view(), name='public_product_detail'),
    path('products/<slug:slug>/reviews/', PublicProductReviewsView.as_view(), name='public_product_reviews'),
]

# Customer API URLs - Authentication required
customer_urlpatterns = [
    # Product reviews
    path('products/<slug:slug>/reviews/', CustomerProductReviewCreateView.as_view(), name='customer_product_review'),
    
    # Wishlist
    path('wishlist/', CustomerWishlistListView.as_view(), name='customer_wishlist'),
    path('wishlist/<int:product_id>/', CustomerWishlistDeleteView.as_view(), name='customer_wishlist_delete'),
]

# Admin API URLs - Admin authentication required
admin_urlpatterns = [
    # Categories
    path('categories/', AdminCategoryListCreateView.as_view(), name='admin_category_list'),
    path('categories/<int:pk>/', AdminCategoryDetailView.as_view(), name='admin_category_detail'),
    
    # Products
    path('products/', AdminProductListCreateView.as_view(), name='admin_product_list'),
    path('products/<int:pk>/', AdminProductDetailView.as_view(), name='admin_product_detail'),
    path('products/<int:pk>/images/', AdminProductImageUploadView.as_view(), name='admin_product_images'),
    path('products/<int:pk>/images/<int:image_id>/', AdminProductImageDeleteView.as_view(), name='admin_product_image_delete'),
    path('products/<int:pk>/stock/', AdminProductStockUpdateView.as_view(), name='admin_product_stock'),
]

# Combined URL patterns for inclusion in main urls.py
urlpatterns = []
