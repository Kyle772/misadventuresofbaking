$(document).ready(function () {
    var $window = $(window),
        $sectionActive = $('.section').first(),
        $sectionNext = $sectionActive.next();

    function updateSection() {
        var windowTop = $(window).scrollTop(),
            sectionTopActive,
            sectionTopNext;

        try {
            sectionTopActive = $sectionActive.offset().top;
            sectionTopNext = $sectionNext.offset().top;
        } catch (TypeError) {
            $sectionNext = $sectionActive;
            try {
                $sectionActive = $sectionActive.prev();
            } catch (err) {
                return false;
            }
            return false;
        }
        
        if (windowTop >= sectionTopNext - 50) {
            if ($sectionNext.offset().top === undefined) {
                console.log("Next is last");
                $sectionActive = $sectionActive.prev();
                $sectionNext = $sectionNext.prev();
                return false;
            }
            $sectionActive = $sectionActive.next();
            $sectionNext = $sectionNext.next();
            return true;
        } else if (windowTop < sectionTopActive - 50) {
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
    
    function backImg(clss) {
        $(clss).each(function () {
            var attr = $(this).attr('data-backImg');

            if (typeof attr !== typeof undefined && attr !== false) {
                $(this).css('background-image', 'url(' + attr + ')');
            }
        });
    }
    
    function txtCol(clss) {
        $(clss).each(function () {
            var attr = $(this).attr('data-backCol');

            if (typeof attr !== typeof undefined && attr !== false) {
                $(this).css('background-color', attr);
            }
        });
    }
    
    /* Begin */
    if (updateSection()) {
        updateText();
    }; 
    
    backImg('.section');
    backImg('.item');
    txtCol('.section'); 
    
//    $(window).on("scroll", _.throttle(function () {
//        if (updateSection()) {
//            updateText();
//        }
//    }, 250));
});