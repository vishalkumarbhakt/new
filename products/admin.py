from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from .models import Category, Product, ProductImage, ProductReview, Wishlist


class ProductImageInline(admin.TabularInline):
    model = ProductImage
    extra = 1
    readonly_fields = ('created_at', 'image_preview')
    fields = ('image', 'image_preview', 'alt_text', 'is_primary', 'display_order')
    
    def image_preview(self, obj):
        if obj.image:
            return format_html('<img src="{}" width="100" />', obj.image.url)
        return "-"
    image_preview.short_description = 'Preview'


class ProductReviewInline(admin.TabularInline):
    model = ProductReview
    extra = 0
    readonly_fields = ('user', 'rating', 'created_at', 'is_verified_purchase')
    fields = ('user', 'rating', 'title', 'is_approved', 'is_verified_purchase', 'created_at')
    can_delete = True


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'slug', 'parent', 'display_order', 'is_active', 
        'is_featured', 'product_count', 'created_at'
    )
    list_filter = ('is_active', 'is_featured', 'parent', 'created_at')
    search_fields = ('name', 'slug', 'description')
    prepopulated_fields = {'slug': ('name',)}
    readonly_fields = ('created_at', 'updated_at', 'product_count', 'full_path')
    ordering = ('display_order', 'name')
    
    fieldsets = (
        (_('Basic Information'), {
            'fields': ('name', 'slug', 'description', 'image', 'parent')
        }),
        (_('Display Settings'), {
            'fields': ('display_order', 'is_active', 'is_featured')
        }),
        (_('SEO'), {
            'fields': ('meta_title', 'meta_description'),
            'classes': ('collapse',)
        }),
        (_('Statistics'), {
            'fields': ('product_count', 'full_path'),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def product_count(self, obj):
        return obj.product_count
    product_count.short_description = 'Products'


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'sku', 'category', 'price', 'discount_price', 
        'stock_quantity', 'stock_status', 'is_active', 'is_featured', 
        'sold_count', 'created_at'
    )
    list_filter = (
        'is_active', 'is_featured', 'is_new', 'is_bestseller',
        'category', 'tax_class', 'is_digital', 'created_at'
    )
    search_fields = ('name', 'sku', 'description', 'brand')
    prepopulated_fields = {'slug': ('name',)}
    readonly_fields = (
        'created_at', 'updated_at', 'published_at', 'view_count', 
        'sold_count', 'effective_price', 'is_on_sale', 'is_in_stock',
        'is_low_stock', 'savings_amount'
    )
    ordering = ('-created_at',)
    date_hierarchy = 'created_at'
    
    fieldsets = (
        (_('Basic Information'), {
            'fields': ('name', 'slug', 'sku', 'description', 'short_description', 'category', 'brand')
        }),
        (_('Pricing'), {
            'fields': ('price', 'discount_price', 'discount_percentage', 'effective_price', 'savings_amount', 'is_on_sale')
        }),
        (_('Inventory'), {
            'fields': ('stock_quantity', 'low_stock_threshold', 'is_track_stock', 'allow_backorder', 'is_in_stock', 'is_low_stock')
        }),
        (_('Product Details'), {
            'fields': ('weight', 'dimensions', 'attributes', 'variants'),
            'classes': ('collapse',)
        }),
        (_('Visibility'), {
            'fields': ('is_active', 'is_featured', 'is_new', 'is_bestseller')
        }),
        (_('SEO'), {
            'fields': ('meta_title', 'meta_description', 'meta_keywords'),
            'classes': ('collapse',)
        }),
        (_('Tax & Shipping'), {
            'fields': ('tax_class', 'is_digital'),
            'classes': ('collapse',)
        }),
        (_('Statistics'), {
            'fields': ('view_count', 'sold_count'),
            'classes': ('collapse',)
        }),
        (_('Timestamps'), {
            'fields': ('created_at', 'updated_at', 'published_at'),
            'classes': ('collapse',)
        })
    )
    
    inlines = [ProductImageInline, ProductReviewInline]
    
    def stock_status(self, obj):
        if not obj.is_track_stock:
            return format_html('<span style="color: gray;">Not tracked</span>')
        if obj.stock_quantity <= 0:
            return format_html('<span style="color: red;">Out of stock</span>')
        if obj.is_low_stock:
            return format_html('<span style="color: orange;">Low stock ({})</span>', obj.stock_quantity)
        return format_html('<span style="color: green;">In stock ({})</span>', obj.stock_quantity)
    stock_status.short_description = 'Stock Status'
    
    actions = ['mark_active', 'mark_inactive', 'mark_featured', 'unmark_featured']
    
    def mark_active(self, request, queryset):
        count = queryset.update(is_active=True)
        self.message_user(request, f'{count} products marked as active.')
    mark_active.short_description = "Mark selected products as active"
    
    def mark_inactive(self, request, queryset):
        count = queryset.update(is_active=False)
        self.message_user(request, f'{count} products marked as inactive.')
    mark_inactive.short_description = "Mark selected products as inactive"
    
    def mark_featured(self, request, queryset):
        count = queryset.update(is_featured=True)
        self.message_user(request, f'{count} products marked as featured.')
    mark_featured.short_description = "Mark selected products as featured"
    
    def unmark_featured(self, request, queryset):
        count = queryset.update(is_featured=False)
        self.message_user(request, f'{count} products unmarked as featured.')
    unmark_featured.short_description = "Remove featured status from selected products"


@admin.register(ProductImage)
class ProductImageAdmin(admin.ModelAdmin):
    list_display = ('product', 'image_preview', 'alt_text', 'is_primary', 'display_order', 'created_at')
    list_filter = ('is_primary', 'created_at')
    search_fields = ('product__name', 'alt_text')
    readonly_fields = ('created_at', 'image_preview')
    ordering = ('product', 'display_order')
    
    def image_preview(self, obj):
        if obj.image:
            return format_html('<img src="{}" width="100" />', obj.image.url)
        return "-"
    image_preview.short_description = 'Preview'


@admin.register(ProductReview)
class ProductReviewAdmin(admin.ModelAdmin):
    list_display = ('product', 'user', 'rating', 'title', 'is_verified_purchase', 'is_approved', 'created_at')
    list_filter = ('rating', 'is_verified_purchase', 'is_approved', 'created_at')
    search_fields = ('product__name', 'user__username', 'title', 'comment')
    readonly_fields = ('created_at', 'updated_at', 'is_verified_purchase')
    ordering = ('-created_at',)
    
    actions = ['approve_reviews', 'reject_reviews']
    
    def approve_reviews(self, request, queryset):
        count = queryset.update(is_approved=True)
        self.message_user(request, f'{count} reviews approved.')
    approve_reviews.short_description = "Approve selected reviews"
    
    def reject_reviews(self, request, queryset):
        count = queryset.update(is_approved=False)
        self.message_user(request, f'{count} reviews rejected.')
    reject_reviews.short_description = "Reject selected reviews"


@admin.register(Wishlist)
class WishlistAdmin(admin.ModelAdmin):
    list_display = ('user', 'product', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('user__username', 'product__name')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)

