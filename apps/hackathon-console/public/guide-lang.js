const current = window.ADAP_I18N.getLang()
const selected = document.getElementById(`lang-${current}`)
if (selected) selected.checked = true
document.querySelectorAll('input[name="lang"]').forEach((input) => {
  input.addEventListener('change', () => {
    if (input.checked) window.ADAP_I18N.setLang(input.id.slice('lang-'.length))
  })
})
