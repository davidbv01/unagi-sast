// @ts-nocheck

describe('My VS Code Extension', () => {
    it('should be able to load VS Code', async () => {
        const workbench = await browser.getWorkbench();
        expect(await workbench.getTitleBar().getTitle()).toBe(
            '[Extension Development Host] Visual Studio Code'
        );
    });
});

