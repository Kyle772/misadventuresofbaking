$(document).ready(function () {
    var $window = $(window),
        $sectionActive = $('.section').first(),
        $sectionNext = $sectionActive.next();

    function updateSection() {
        console.log($sectionNext);
        console.log($('.section').last());
        
        if ($sectionNext === $('.section').last()) {
            console.log("Next is last")
            return false;
        }
    
        var windowTop = $(window).scrollTop(),
            sectionTopActive = $sectionActive.offset().top,
            sectionTopNext = $sectionNext.offset().top;
        
        console.log("WindowTop: " + windowTop);
        console.log("Section Top: " + sectionTopActive);
        console.log("Section Top Next: " + sectionTopNext);

        if (windowTop >= sectionTopNext) {
            $sectionActive = $sectionActive.next();
            $sectionNext = $sectionNext.next();
            return true;
        } else if (windowTop < sectionTopActive) {
            $sectionActive = $sectionActive.prev();
            $sectionNext = $sectionNext.prev();
            return true;
        } else {
            return true;
        }
    }
    
    function updateText() {
        var attr = $sectionActive.attr('data-textOverlay');
        
        if (typeof attr !== typeof undefined && attr !== false) {
            $('.header').css('color', attr);
            $('.header').css('fill', attr);
        }
    }
    
    /* Begin */
    if (updateSection()) {
        updateText();
    }
    
    $(".section").each(function () {
        var attr = $(this).attr('data-backImg');

        if (typeof attr !== typeof undefined && attr !== false) {
            $(this).css('background-image', 'url(' + attr + ')');
        }
        
        attr = $(this).attr('data-backCol');

        if (typeof attr !== typeof undefined && attr !== false) {
            $(this).css('background-color', attr);
        }
    });
    $(window).on("scroll", function () {
        if (updateSection()) {
            updateText();
        }
    });
});