window.addEventListener('scroll', function() {
    const navbar = document.querySelector(".header") ;
    const scrollPosition = window.scrollY;
    if (scrollPosition > 10)
    {
        navbar.classList.add("scrolled");
    }
    else navbar.classList.remove("scrolled") ;
})

window.addEventListener('DOMContentLoaded', ()=>{
    const des = document.querySelector(".description") ;
    setTimeout(()=>{
        des.classList.add("visible") ;
    },500) ;
})


function openSidebar() {
    const nav = document.querySelector('.sidebar') ;
    nav.style.display = 'block' ;
}

function closeSidebar() {
    const nav = document.querySelector('.sidebar') ;
    nav.style.display = 'none' ;
}