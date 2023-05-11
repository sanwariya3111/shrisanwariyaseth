(function ($) {
    "use strict";
    // preloder
    $(window).on('load', function () {
        $('.preloader').fadeOut(1000);
    })

        

    $(document).ready(function () {
        // lightcase 
        $('a[data-rel^=lightcase]').lightcase();

        //Header
        var fixed_top = $(".header__bottom");
        $(window).on('scroll', function () {
            if ($(this).scrollTop() > 200) {
                fixed_top.addClass("header__bottom-fiexd animated fadeInDown");
            } else {
                fixed_top.removeClass("header__bottom-fiexd animated fadeInDown");
            }
        });

        // Header Cart js
        $('.search__icon').on('click', function() {
            $('.header-form').addClass('active');
        })
        $('.header-form .bg-lay').on('click', function() {
            $('.header-form').removeClass('active');
        })
        $('.cart__icon, .side-sidebar-close-btn').on('click', function () {
            $(this).toggleClass('active');
            $('.overlay').toggleClass('active');
            $('.cart-sidebar-area').toggleClass('active');
        })
        $('.remove-cart').on('click', function (e) {
            e.preventDefault();
            $(this).parent().parent().hide(300);
        });
        $('.overlay').on('click', function () {
            $(this).removeClass('active');
            $('.cart-sidebar-area').removeClass('active');
        })
        // Header Cart js
        
        //Toggle Menu
        // $('.bar').on('click', () => {
        //     $('.header-area ').toggleClass('show');
        // });
        // $('.menu ul li a').on('click', () => {
        //     $('.navbar-collapse').removeClass('show');
        //     $('.navbar-toggler').addClass('collapsed');
        // });

        

        // Header Section Menu Part
        $("ul li ul").parent("li").addClass("menu-item-has-children");

        $('.header__menu ul li a').on('click', function(e) {
            var element = $(this).parent('li');
            if (element.hasClass('open')) {
                element.removeClass('open');
                element.find('li').removeClass('open');
                element.find('ul').slideUp(1000,"swing");
            }
            else {
                element.addClass('open');
                element.children('ul').slideDown(1000,"swing");
                element.siblings('li').children('ul').slideUp(1000,"swing");
                element.siblings('li').removeClass('open');
                element.siblings('li').find('li').removeClass('open');
                element.siblings('li').find('ul').slideUp(1000,"swing");
            }
        });

        // scrollReveal Init
        if (screen.width > 576) {
            $(document).ready(function () {
                new WOW().init();
            });
        }
        
        // Banner slider
        var swiper = new Swiper('.banner__slider', {
            loop: true,
            autoplay: {
                delay: 10000,
                disableOnInteraction: false,
            },
            pagination: {
                el: ".banner__pagination",
                clickable: true,
            },
        });

        // Blog slider
        var swiper = new Swiper('.blog__slider', {
            loop: true,
            autoplay: {
                delay: 10000,
                disableOnInteraction: false,
            },
            pagination: {
                el: ".blog__pagination",
                clickable: true,
            },
        });


        //qoute slider
        var swiper = new Swiper('.qoute__slider', {
            slidesPerView: 1,
            spaceBetween: 20,
            autoplay: {
                delay: 10000,
                disableOnInteraction: false,
            },
            loop: true,
        });


        //qoute slider
        var swiper = new Swiper('.sponsor__slider', {
            slidesPerView: 1,
            spaceBetween: 20,
            autoplay: {
                delay: 5000,
                disableOnInteraction: false,
            },
            loop: true,
            breakpoints: {
                768: {
                    slidesPerView: 4,
                },
                567: {
                    slidesPerView: 2,
                },
            },
        });

        
        // shop cart + - start here
        var CartPlusMinus = $('.cart-plus-minus');
        $(".qtybutton").on("click", function() {
            var $button = $(this);
            var oldValue = $button.parent().find("input").val();
            if ($button.text() === "+") {
                var newVal = parseFloat(oldValue) + 1;
            } else {
                if (oldValue > 0) {
                    var newVal = parseFloat(oldValue) - 1;
                } else {
                    newVal = 1;
                }
            }
            $button.parent().find("input").val(newVal);
        });


        
        // model option start here
        $(function() {
            $('.view-modal').on('click', function () {
                $('.modal').addClass('show');
            });
            $('.close').on('click', function () {
                $('.modal').removeClass('show');
            });
        });

        // shop sidebar menu
        
        // $(".sidebar__catagory>li>ul").parent("li").addClass("catmenu-item-has-children");
        $('.sidebar__catagory li a').on('click', function (e) {
            var element = $(this).parent('li');
            if (element.hasClass('open')) {
                element.removeClass('open');
                element.find('li').removeClass('open');
                element.find('ul').slideUp(300, "swing");
            } else {
                element.addClass('open');
                element.children('ul').slideDown(300, "swing");
                element.siblings('li').children('ul').slideUp(300, "swing");
                element.siblings('li').removeClass('open');
                element.siblings('li').find('li').removeClass('open');
                element.siblings('li').find('ul').slideUp(300, "swing");
            }
        })


        // product single thumb slider
        $(function() {
            var galleryThumbs = new Swiper('.pro-single-thumbs', {
                spaceBetween: 10,
                slidesPerView: 3,
                loop: true,
                freeMode: true,
                loopedSlides: 2,
                watchSlidesVisibility: true,
                watchSlidesProgress: true,
                navigation: {
                nextEl: '.pro-single-next',
                prevEl: '.pro-single-prev',
                },
            });
            var galleryTop = new Swiper('.pro-single-top', {
                spaceBetween: 10,
                loop:true,
                loopedSlides: 1,
                thumbs: {
                    swiper: galleryThumbs,
                },
            });
        });

        
        //Review Tabs
        $('ul.review-nav').on('click', 'li', function (e) {
            e.preventDefault();
            var reviewContent = $('.review-content');
            var viewRev = $(this).data('target');
            $('ul.review-nav li').removeClass('active');
            $(this).addClass('active');
            reviewContent.removeClass('review-content-show description-show').addClass(viewRev);
        });

        // product view mode change js
        $(function() {
            $('.product-view-mode').on('click', 'a', function (e) {
                e.preventDefault();
                var shopProductWrap = $('.shop-product-wrap');
                var viewMode = $(this).data('target');
                $('.product-view-mode a').removeClass('active');
                $(this).addClass('active');
                shopProductWrap.removeClass('gridlist list').addClass(viewMode);
            });
        });

        //Isotope
        jQuery(window).on('load',function() { 
            var $grid = $('.grid').isotope({
                itemSelector: '.col-12',
                masonry: {
                    columnWidth: 0
                }
            })

            // filter items on button click
            $('.gallery__filter ul').on('click', 'li', function () {
                var filterValue = $(this).attr('data-filter');
                $grid.isotope({
                    filter: filterValue
                });
            });

            $('.gallery__filter ul').each(function (i, buttonGroup) {
                var $buttonGroup = $(buttonGroup);
                $buttonGroup.on('click', 'li', function () {
                    $buttonGroup.find('.active').removeClass('active');
                    $(this).addClass('active');
                });
            });
        });

        //Countdown js initialization
        document.addEventListener('readystatechange', event => {
            if (event.target.readyState === "complete") {
                var clockdiv = document.getElementsByClassName("count-down");
                var countDownDate = new Array();
                for (var i = 0; i < clockdiv.length; i++) {
                    countDownDate[i] = new Array();
                    countDownDate[i]['el'] = clockdiv[i];
                    countDownDate[i]['time'] = new Date(clockdiv[i].getAttribute('data-date')).getTime();
                    countDownDate[i]['days'] = 0;
                    countDownDate[i]['hours'] = 0;
                    countDownDate[i]['seconds'] = 0;
                    countDownDate[i]['minutes'] = 0;
                }
                var countdownfunction = setInterval(function () {
                    for (var i = 0; i < countDownDate.length; i++) {
                        var now = new Date().getTime();
                        var distance = countDownDate[i]['time'] - now;
                        countDownDate[i]['days'] = Math.floor(distance / (1000 * 60 * 60 * 24));
                        countDownDate[i]['hours'] = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                        countDownDate[i]['minutes'] = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                        countDownDate[i]['seconds'] = Math.floor((distance % (1000 * 60)) / 1000);
                        if (distance < 0) {
                            countDownDate[i]['el'].querySelector('.days').innerHTML = 0;
                            countDownDate[i]['el'].querySelector('.hours').innerHTML = 0;
                            countDownDate[i]['el'].querySelector('.minutes').innerHTML = 0;
                            countDownDate[i]['el'].querySelector('.seconds').innerHTML = 0;
                        } else {
                            countDownDate[i]['el'].querySelector('.days').innerHTML = countDownDate[i]['days'];
                            countDownDate[i]['el'].querySelector('.hours').innerHTML = countDownDate[i]['hours'];
                            countDownDate[i]['el'].querySelector('.minutes').innerHTML = countDownDate[i]['minutes'];
                            countDownDate[i]['el'].querySelector('.seconds').innerHTML = countDownDate[i]['seconds'];
                        }
                    }
                }, 1000);
            }
        });

        

        // scroll up start here
        $(function(){
            $(window).scroll(function(){
                if ($(this).scrollTop() > 300) {
                    $('.scrollToTop').css({'bottom':'2%', 'opacity':'1','transition':'all .5s ease'});
                } else {
                    $('.scrollToTop').css({'bottom':'-30%', 'opacity':'0','transition':'all .5s ease'})
                }
            });
            //Click event to scroll to top
            $('.scrollToTop').on('click', function(){
                $('html, body').animate({scrollTop : 0},500);
                return false;
            });
        });

        // ajax contact form
        $(function() {
            var form = $('#contact-form');
            var formMessages = $('.form-message');
            $(form).submit(function(e) {
                e.preventDefault();
                var formData = $(form).serialize();
                $.ajax({
                    type: 'POST',
                    url: $(form).attr('action'),
                    data: formData
                })
                .done(function(response) {
                    $(formMessages).removeClass('error');
                    $(formMessages).addClass('success');
                    $(formMessages).text(response);
                    $('#contact-form input, #contact-form textarea').val('');
                })
                .fail(function(data) {
                    $(formMessages).removeClass('success');
                    $(formMessages).addClass('error');
                    if (data.responseText !== '') {
                        $(formMessages).text(data.responseText);
                    } else {
                        $(formMessages).text('Oops! An error occured and your message could not be sent.');
                    }
                });
            });
        });
    });
})(jQuery);