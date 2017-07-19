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
    
    function toClipboard(jElement) {
        var temp = $("<input>");
        $("body").append(temp);
        console.log("Appended");
        temp.val(jElement.attr("data-clipboard")).select();
        console.log("assigned text");
        document.execCommand("copy");
        console.log("copied");
        temp.remove();
        console.log("removed");
    }
    
    function updateText() {
        var attr = $sectionActive.attr('data-textoverlay');
        
        if (typeof attr !== typeof undefined && attr !== false) {
            $('.header').css('color', attr);
            $('.header').css('fill', attr);
        }
    }
    
    function backimg(clss) {
        $(clss).each(function () {
            var attr = $(this).attr('data-backimg');

            if (typeof attr !== typeof undefined && attr !== false) {
                console.log("Assigning background-image in css");
                $(this).css('background-image', 'url(' + attr + ')');
                console.log("Assigned to " + clss);
                console.log($(this));
            }
        });
    }
    
    function txtCol(clss) {
        $(clss).each(function () {
            var attr = $(this).attr('data-backcol');

            if (typeof attr !== typeof undefined && attr !== false) {
                $(this).css('background-color', attr);
            }
        });
    }
    
    /* Begin */
    
    if (updateSection()) {
        updateText();
    }

    backimg('.section');
    backimg('.item');
    backimg('.img');
    txtCol('.section');

    $("div[data-clipboard]").on("click", function () {
        toClipboard($(this));
    });
});