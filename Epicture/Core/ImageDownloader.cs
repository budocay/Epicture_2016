using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.UI.Popups;
using Windows.UI.Xaml.Media.Imaging;

namespace Epicture
{
    internal class ImageDownloader
    {
        public async Task<ObservableCollection<MenuItem>> DownloadImageFlickr(FlickrAuth.RootObject root, object Imgur,
            ObservableCollection<MenuItem> items,
            ObservableCollection<MenuItem> _ifavItems, bool IsFavButtonPressed)
        {
            var ImageAlreadyExist = false;
            if (root.Stat == "ok")
            {
                foreach (var VARIABLE in root.Photos.Photo)
                    try
                    {
                        if (items.Count > 0)
                            foreach (var menuItem in items)
                                if (menuItem.IdPhoto == VARIABLE.Id)
                                {
                                    var smg_dialog =
                                        new MessageDialog(
                                            "L'image que vous essayer d'avoir existe déja dans votre Gallerie.");
                                    await smg_dialog.ShowAsync();
                                    ImageAlreadyExist = true;
                                }
                                else
                                {
                                    ImageAlreadyExist = false;
                                }
                        if (ImageAlreadyExist) continue;
                        var rootFolder =
                            await ApplicationData.Current.LocalFolder.CreateFolderAsync("Epicture\\FlickrImages",
                                CreationCollisionOption.OpenIfExists);
                        var coverpic_file = await rootFolder.CreateFileAsync(VARIABLE.Title + ".jpg",
                            CreationCollisionOption.OpenIfExists);

                        var photoUrl = "http://farm{0}.staticflickr.com/{1}/{2}_{3}_n.jpg";

                        var baseFlickrURL = string.Format(photoUrl, VARIABLE.Farm, VARIABLE.Server, VARIABLE.Id,
                            VARIABLE.Secret);
                        var bitmapImage = new BitmapImage(new Uri(baseFlickrURL))
                        {
                            DecodePixelHeight = 100,
                            DecodePixelWidth = 100
                        };
                        try
                        {
                            var client = new HttpClient(); // Create HttpClient
                            var buffer = await client.GetByteArrayAsync(baseFlickrURL); // Download file
                            using (var stream = await coverpic_file.OpenStreamForWriteAsync())
                            {
                                stream.Write(buffer, 0, buffer.Length); // Save
                            }

                            items.Add(new MenuItem
                            {
                                Name = coverpic_file.Path,
                                IdPhoto = VARIABLE.Id
                            });
                            if (IsFavButtonPressed)
                                _ifavItems.Add(new MenuItem
                                {
                                    Name = coverpic_file.Path,
                                    IdPhoto = VARIABLE.Id
                                });
                        }
                        catch (Exception e)
                        {
                            var failDialog =
                                new MessageDialog("Download failure Images Flickr\n" + e.Message);
                            await failDialog.ShowAsync();
                        }
                    }
                    catch (Exception e)
                    {
                        var failDialog = new MessageDialog(e.Message);
                        await failDialog.ShowAsync();
                    }
            }
            // Implémenter le Download Pour ImGur
            return items;
        }
    }
}