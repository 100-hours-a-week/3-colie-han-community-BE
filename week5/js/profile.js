document.addEventListener("DOMContentLoaded", async () => {
    const baseUrl = "http://localhost:8080";
    const DEFAULT_IMG = "../assets/profile-sample.png";
    const imgEl = document.querySelector(".profile-img");

    if (!imgEl) return;

    // 기본 이미지 먼저 표시
    imgEl.src = DEFAULT_IMG;
    imgEl.onerror = () => { imgEl.src = DEFAULT_IMG; };

    try {
        const res = await fetch(`${baseUrl}/users`, {
            method: "GET",
            credentials: "include",
        });

        if (!res.ok) return; // 로그인 안 된 경우 기본이미지 유지

        const user = await res.json();
        const url = user.profileImageUrl;

        if (!url || !url.trim()) return;

        const finalUrl = url.startsWith("http")
            ? url
            : `${baseUrl}${url.startsWith("/") ? "" : "/"}${url}`;

        imgEl.src = `${finalUrl}?v=${Date.now()}`;
    } catch (e) {
        console.error("프로필 불러오기 실패:", e);
    }

    const title = document.querySelector(".header h1");
    if (title) {
        title.style.cursor = "pointer";
        title.addEventListener("click", () => {
            window.location.href = "./postList.html";
        });
    }
});
