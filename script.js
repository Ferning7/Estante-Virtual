document.addEventListener('DOMContentLoaded', () => {
  const searchInput = document.getElementById('searchInput');
  const bookCards = Array.from(document.querySelectorAll('.book-card'));

  searchInput.addEventListener('input', () => {
    const filtro = searchInput.value.toLowerCase();

    bookCards.forEach(card => {
      const titulo = card.querySelector('h3').textContent.toLowerCase();
      const autor = card.querySelector('p').textContent.toLowerCase();

      if (titulo.includes(filtro) || autor.includes(filtro)) {
        card.style.display = '';
      } else {
        card.style.display = 'none';
      }
    });
  });
});
