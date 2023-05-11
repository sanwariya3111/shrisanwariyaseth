$(window).scroll(function() {
    var hT = $('.donaterange__content').offset().top,
        hH = $('.donaterange__content').outerHeight(),
        wH = $(window).height(),
        wS = $(this).scrollTop();
    if (wS > (hT+hH-1.4*wH)){
        jQuery(document).ready(function(){
            jQuery('.donaterange__bars').each(function(){
                jQuery(this).find('.donaterange__bar').animate({
                    width:jQuery(this).attr('data-percent')
                }, 5000); // 5 seconds
            });
        });
    }
});