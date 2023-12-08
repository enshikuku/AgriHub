const load = document.querySelector('.loadermain')

window.addEventListener("load", function(){
    load.style.display = 'none'
})

function closeNav() {
    document.querySelector('#nav-check').checked = false
}
