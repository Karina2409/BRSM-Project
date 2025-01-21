document.getElementById('uploadForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById('fileInput');
  if (!fileInput.files.length) {
    alert('Выберите файл!');
    return;
  }

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);

  try {
    const token = localStorage.getItem("authToken");
    const response = await fetch('http://localhost:8080/students/import', {
      method: 'POST',
      body: formData,
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (response.ok) {
      alert('Файл успешно загружен!');
    } else {
      alert('Ошибка при загрузке файла');
    }
  } catch (err) {
    console.error('Ошибка:', err);
    alert('Не удалось подключиться к серверу');
  }
});