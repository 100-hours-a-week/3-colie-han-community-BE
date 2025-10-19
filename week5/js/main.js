document.addEventListener("DOMContentLoaded", () => {
    const enterBtn = document.querySelector(".enter-btn");


    console.log('document.cookie ->', document.cookie);

    enterBtn.addEventListener("click", async () => {
        try {

            const response = await fetch("http://localhost:8080/posts", {
                method: "GET",
                credentials: "include",
            });

            if (response.status === 401 || response.status === 403) {
                alert("로그인이 필요합니다.");
                window.location.href = "./login.html";
                return;
            }

            if (!response.ok) {
                throw new Error("서버 오류");
            }

            window.location.href = "./postList.html";
        } catch (error) {
            console.error("인증 확인 중 오류:", error);
            alert("로그인 정보를 확인할 수 없습니다. 다시 로그인해주세요.");
            window.location.href = "./login.html";
        }
    });
});
