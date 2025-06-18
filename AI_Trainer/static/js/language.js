// Функция для применения переводов
function applyTranslations() {
    const lang = sessionStorage.getItem('lang') || document.documentElement.lang || 'ua'; // Получаем язык из sessionStorage или атрибута lang
    const elements = document.querySelectorAll('[data-i18n]');

    elements.forEach(element => {
        const key = element.getAttribute('data-i18n');
        if (translations[lang] && translations[lang][key]) {
            element.textContent = translations[lang][key];
        }
    });

    // Обновляем заголовок страницы
    const titleElement = document.querySelector('title[data-i18n]');
    if (titleElement) {
        const titleKey = titleElement.getAttribute('data-i18n');
        if (translations[lang] && translations[lang][titleKey]) {
            document.title = translations[lang][titleKey];
        }
    }
}

// При загрузке страницы применяем переводы
document.addEventListener('DOMContentLoaded', () => {
    applyTranslations();
});