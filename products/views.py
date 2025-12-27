"""
Product views for e-commerce backend.
Provides public, customer, and admin APIs for product management.
"""
import logging
from django.shortcuts import get_object_or_404
from django.db.models import Q, Avg
from rest_framework import generics, status, filters
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.parsers import MultiPartParser, FormParser

from .models import Category, Product, ProductImage, ProductReview, Wishlist
from .serializers import (
    CategorySerializer, CategoryBasicSerializer, CategoryCreateSerializer,
    ProductListSerializer, ProductDetailSerializer, ProductCreateSerializer,
    ProductImageSerializer, ProductImageCreateSerializer,
    ProductReviewSerializer, ProductReviewCreateSerializer,
    WishlistSerializer, WishlistCreateSerializer
)
from .permissions import IsAdminOrReadOnly

logger = logging.getLogger(__name__)


# ============== Public Category Views ==============

class PublicCategoryListView(generics.ListAPIView):
    """
    Public API to list all active categories.
    GET /api/public/categories/
    """
    permission_classes = [AllowAny]
    serializer_class = CategorySerializer
    
    def get_queryset(self):
        queryset = Category.objects.filter(is_active=True)
        
        # Filter by parent (null for root categories)
        parent = self.request.query_params.get('parent')
        if parent == 'null' or parent == 'root':
            queryset = queryset.filter(parent__isnull=True)
        elif parent:
            queryset = queryset.filter(parent_id=parent)
        
        # Filter featured categories
        featured = self.request.query_params.get('featured')
        if featured and featured.lower() == 'true':
            queryset = queryset.filter(is_featured=True)
        
        return queryset.order_by('display_order', 'name')


class PublicCategoryDetailView(generics.RetrieveAPIView):
    """
    Public API to get category details by slug.
    GET /api/public/categories/<slug>/
    """
    permission_classes = [AllowAny]
    serializer_class = CategorySerializer
    lookup_field = 'slug'
    
    def get_queryset(self):
        return Category.objects.filter(is_active=True)


# ============== Public Product Views ==============

class PublicProductListView(generics.ListAPIView):
    """
    Public API to list products with filtering and search.
    GET /api/public/products/
    
    Query Parameters:
    - category: Filter by category slug
    - search: Search in name and description
    - min_price: Minimum price filter
    - max_price: Maximum price filter
    - brand: Filter by brand
    - featured: Filter featured products
    - new: Filter new arrivals
    - bestseller: Filter bestsellers
    - in_stock: Filter in-stock products only
    - ordering: Sort by (price, -price, name, -name, created_at, -created_at, sold_count)
    """
    permission_classes = [AllowAny]
    serializer_class = ProductListSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description', 'brand', 'sku']
    ordering_fields = ['price', 'name', 'created_at', 'sold_count', 'view_count']
    ordering = ['-created_at']
    
    def get_queryset(self):
        queryset = Product.objects.filter(is_active=True).select_related('category')
        
        # Filter by category
        category = self.request.query_params.get('category')
        if category:
            queryset = queryset.filter(
                Q(category__slug=category) | Q(category__parent__slug=category)
            )
        
        # Filter by price range
        min_price = self.request.query_params.get('min_price')
        max_price = self.request.query_params.get('max_price')
        if min_price:
            queryset = queryset.filter(price__gte=min_price)
        if max_price:
            queryset = queryset.filter(price__lte=max_price)
        
        # Filter by brand
        brand = self.request.query_params.get('brand')
        if brand:
            queryset = queryset.filter(brand__iexact=brand)
        
        # Filter featured products
        featured = self.request.query_params.get('featured')
        if featured and featured.lower() == 'true':
            queryset = queryset.filter(is_featured=True)
        
        # Filter new arrivals
        new = self.request.query_params.get('new')
        if new and new.lower() == 'true':
            queryset = queryset.filter(is_new=True)
        
        # Filter bestsellers
        bestseller = self.request.query_params.get('bestseller')
        if bestseller and bestseller.lower() == 'true':
            queryset = queryset.filter(is_bestseller=True)
        
        # Filter on-sale products
        on_sale = self.request.query_params.get('on_sale')
        if on_sale and on_sale.lower() == 'true':
            queryset = queryset.filter(discount_price__isnull=False)
        
        # Filter in-stock products
        in_stock = self.request.query_params.get('in_stock')
        if in_stock and in_stock.lower() == 'true':
            queryset = queryset.filter(
                Q(stock_quantity__gt=0) | Q(is_track_stock=False)
            )
        
        return queryset


class PublicProductDetailView(generics.RetrieveAPIView):
    """
    Public API to get product details by slug.
    GET /api/public/products/<slug>/
    """
    permission_classes = [AllowAny]
    serializer_class = ProductDetailSerializer
    lookup_field = 'slug'
    
    def get_queryset(self):
        return Product.objects.filter(is_active=True).select_related('category')
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        # Increment view count
        instance.increment_view_count()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class PublicProductReviewsView(generics.ListAPIView):
    """
    Public API to list product reviews.
    GET /api/public/products/<slug>/reviews/
    """
    permission_classes = [AllowAny]
    serializer_class = ProductReviewSerializer
    
    def get_queryset(self):
        slug = self.kwargs.get('slug')
        product = get_object_or_404(Product, slug=slug, is_active=True)
        return ProductReview.objects.filter(
            product=product,
            is_approved=True
        ).order_by('-created_at')


# ============== Customer Views ==============

class CustomerProductReviewCreateView(generics.CreateAPIView):
    """
    Customer API to create product review.
    POST /api/customer/products/<slug>/reviews/
    """
    permission_classes = [IsAuthenticated]
    serializer_class = ProductReviewCreateSerializer
    
    def perform_create(self, serializer):
        slug = self.kwargs.get('slug')
        product = get_object_or_404(Product, slug=slug, is_active=True)
        serializer.save(product=product)


class CustomerWishlistListView(generics.ListCreateAPIView):
    """
    Customer API to list and add wishlist items.
    GET /api/customer/wishlist/
    POST /api/customer/wishlist/
    """
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return WishlistCreateSerializer
        return WishlistSerializer
    
    def get_queryset(self):
        return Wishlist.objects.filter(user=self.request.user).select_related('product')
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        wishlist_item = serializer.save()
        
        return Response({
            'status': 'success',
            'message': 'Product added to wishlist',
            'data': WishlistSerializer(wishlist_item, context={'request': request}).data
        }, status=status.HTTP_201_CREATED)


class CustomerWishlistDeleteView(generics.DestroyAPIView):
    """
    Customer API to remove wishlist item.
    DELETE /api/customer/wishlist/<product_id>/
    """
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        product_id = self.kwargs.get('product_id')
        return get_object_or_404(
            Wishlist, 
            user=self.request.user, 
            product_id=product_id
        )
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        product_name = instance.product.name
        instance.delete()
        
        return Response({
            'status': 'success',
            'message': f'{product_name} removed from wishlist'
        }, status=status.HTTP_200_OK)


# ============== Admin Views ==============

class AdminCategoryListCreateView(generics.ListCreateAPIView):
    """
    Admin API to list and create categories.
    GET /api/admin/categories/
    POST /api/admin/categories/
    """
    permission_classes = [IsAdminUser]
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CategoryCreateSerializer
        return CategorySerializer
    
    def get_queryset(self):
        return Category.objects.all().order_by('display_order', 'name')
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        category = serializer.save()
        
        return Response({
            'status': 'success',
            'message': 'Category created successfully',
            'data': CategorySerializer(category, context={'request': request}).data
        }, status=status.HTTP_201_CREATED)


class AdminCategoryDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Admin API to get, update, or delete category.
    GET /api/admin/categories/<pk>/
    PUT /api/admin/categories/<pk>/
    DELETE /api/admin/categories/<pk>/
    """
    permission_classes = [IsAdminUser]
    serializer_class = CategoryCreateSerializer
    queryset = Category.objects.all()
    
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        return Response({
            'status': 'success',
            'data': CategorySerializer(instance, context={'request': request}).data
        })
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        return Response({
            'status': 'success',
            'message': 'Category updated successfully',
            'data': CategorySerializer(instance, context={'request': request}).data
        })
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        name = instance.name
        
        # Check if category has products
        if instance.products.exists():
            return Response({
                'status': 'error',
                'message': 'Cannot delete category with associated products'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        instance.delete()
        return Response({
            'status': 'success',
            'message': f'Category "{name}" deleted successfully'
        })


class AdminProductListCreateView(generics.ListCreateAPIView):
    """
    Admin API to list and create products.
    GET /api/admin/products/
    POST /api/admin/products/
    """
    permission_classes = [IsAdminUser]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'sku', 'description', 'brand']
    ordering_fields = ['price', 'name', 'created_at', 'stock_quantity', 'sold_count']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ProductCreateSerializer
        return ProductListSerializer
    
    def get_queryset(self):
        queryset = Product.objects.all().select_related('category')
        
        # Filter by status
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Filter by category
        category = self.request.query_params.get('category')
        if category:
            queryset = queryset.filter(category_id=category)
        
        # Filter low stock
        low_stock = self.request.query_params.get('low_stock')
        if low_stock and low_stock.lower() == 'true':
            queryset = queryset.filter(
                stock_quantity__lte=models.F('low_stock_threshold'),
                is_track_stock=True
            )
        
        return queryset
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        product = serializer.save()
        
        logger.info(f"Product created: {product.name} (SKU: {product.sku}) by {request.user.username}")
        
        return Response({
            'status': 'success',
            'message': 'Product created successfully',
            'data': ProductDetailSerializer(product, context={'request': request}).data
        }, status=status.HTTP_201_CREATED)


class AdminProductDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Admin API to get, update, or delete product.
    GET /api/admin/products/<pk>/
    PUT /api/admin/products/<pk>/
    DELETE /api/admin/products/<pk>/
    """
    permission_classes = [IsAdminUser]
    queryset = Product.objects.all()
    
    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return ProductCreateSerializer
        return ProductDetailSerializer
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        logger.info(f"Product updated: {instance.name} (SKU: {instance.sku}) by {request.user.username}")
        
        return Response({
            'status': 'success',
            'message': 'Product updated successfully',
            'data': ProductDetailSerializer(instance, context={'request': request}).data
        })
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        name = instance.name
        sku = instance.sku
        
        instance.delete()
        logger.info(f"Product deleted: {name} (SKU: {sku}) by {request.user.username}")
        
        return Response({
            'status': 'success',
            'message': f'Product "{name}" deleted successfully'
        })


class AdminProductImageUploadView(generics.CreateAPIView):
    """
    Admin API to upload product images.
    POST /api/admin/products/<pk>/images/
    """
    permission_classes = [IsAdminUser]
    serializer_class = ProductImageCreateSerializer
    parser_classes = [MultiPartParser, FormParser]
    
    def create(self, request, *args, **kwargs):
        product_id = self.kwargs.get('pk')
        product = get_object_or_404(Product, pk=product_id)
        
        # Handle multiple image uploads
        images = request.FILES.getlist('images') or [request.FILES.get('image')]
        created_images = []
        
        for image in images:
            if image:
                is_primary = request.data.get('is_primary', 'false').lower() == 'true'
                alt_text = request.data.get('alt_text', '')
                
                product_image = ProductImage.objects.create(
                    product=product,
                    image=image,
                    alt_text=alt_text,
                    is_primary=is_primary and len(created_images) == 0
                )
                created_images.append(product_image)
        
        return Response({
            'status': 'success',
            'message': f'{len(created_images)} image(s) uploaded successfully',
            'data': ProductImageSerializer(created_images, many=True, context={'request': request}).data
        }, status=status.HTTP_201_CREATED)


class AdminProductImageDeleteView(generics.DestroyAPIView):
    """
    Admin API to delete product image.
    DELETE /api/admin/products/<pk>/images/<image_id>/
    """
    permission_classes = [IsAdminUser]
    
    def get_object(self):
        product_id = self.kwargs.get('pk')
        image_id = self.kwargs.get('image_id')
        return get_object_or_404(ProductImage, pk=image_id, product_id=product_id)
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        
        return Response({
            'status': 'success',
            'message': 'Image deleted successfully'
        })


class AdminProductStockUpdateView(APIView):
    """
    Admin API to update product stock.
    PATCH /api/admin/products/<pk>/stock/
    """
    permission_classes = [IsAdminUser]
    
    def patch(self, request, pk):
        product = get_object_or_404(Product, pk=pk)
        
        action = request.data.get('action', 'set')  # set, add, subtract
        quantity = request.data.get('quantity')
        
        if quantity is None:
            return Response({
                'status': 'error',
                'message': 'Quantity is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            quantity = int(quantity)
        except ValueError:
            return Response({
                'status': 'error',
                'message': 'Quantity must be a number'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if action == 'set':
            product.stock_quantity = max(0, quantity)
        elif action == 'add':
            product.increment_stock(quantity)
        elif action == 'subtract':
            product.decrement_stock(quantity)
        else:
            return Response({
                'status': 'error',
                'message': 'Invalid action. Use set, add, or subtract'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        product.save()
        
        logger.info(f"Stock updated for {product.name}: {action} {quantity} by {request.user.username}")
        
        return Response({
            'status': 'success',
            'message': f'Stock updated successfully',
            'data': {
                'product_id': product.id,
                'product_name': product.name,
                'stock_quantity': product.stock_quantity,
                'is_in_stock': product.is_in_stock,
                'is_low_stock': product.is_low_stock
            }
        })
